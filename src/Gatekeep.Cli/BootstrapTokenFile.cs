namespace Gatekeep.Cli;

/// <summary>Why the token directory can't take a token, or <see cref="Ready"/>.</summary>
internal enum TokenDirectoryCheck
{
    Ready,
    Missing,
    SymbolicLink,
    NotPrivate,
    NotWritable,
    TokenNotRegular,
}

/// <summary>
/// The bootstrap token file (Story 1.19): <c>bootstrap-token</c> in the token directory, which
/// the <c>cli</c> service bind-mounts from <c>bootstrap/</c> in the host secrets directory. The
/// token goes first to a temporary file created with mode <c>0600</c>, never wider, and synced
/// to disk. <see cref="Publish"/> keeps a hard link to the previous token, then renames the new
/// one over it; <see cref="Restore"/> puts the previous one back if the row isn't committed, and
/// <see cref="Complete"/> drops it once it is. Every rename is followed by a directory sync. A
/// temporary file not published is deleted on dispose. Nothing here changes a mode, and no
/// member ever prints the token.
/// </summary>
internal sealed class BootstrapTokenFile : IDisposable
{
    public const string FileName = "bootstrap-token";

    private const string Prefix = "." + FileName + ".";

    private const uint GroupOrOtherWrite = 0x12; // 0022
    private const uint GroupOrOtherRead = 0x24; // 0044

    /// <summary>
    /// Leftovers of a run that died are swept once this old. A younger one may belong to a run
    /// waiting on the row lock right now, which needs its file.
    /// </summary>
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(10);

    private readonly string _directory;

    private string? _staged;
    private string? _previous;
    private bool _published;

    public BootstrapTokenFile(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        _directory = directory;
    }

    public string PublishedPath => Path.Combine(_directory, FileName);

    public bool Published => _published;

    /// <summary>
    /// Whether a token can go here: a real directory, not a link, owned by this user and writable
    /// by nobody else, holding no token file that is a link or not a regular file, in which a file
    /// can be created. It sweeps stale leftovers, and warns when others can read the directory.
    /// </summary>
    public TokenDirectoryCheck Check(TextWriter warnings)
    {
        var directory = Native.Status(_directory);
        if (!directory.Exists)
        {
            return TokenDirectoryCheck.Missing;
        }

        if (directory.IsSymbolicLink)
        {
            return TokenDirectoryCheck.SymbolicLink;
        }

        if (!directory.IsDirectory)
        {
            return TokenDirectoryCheck.Missing;
        }

        if (directory.Uid != Native.EffectiveUid || (directory.Mode & GroupOrOtherWrite) != 0)
        {
            return TokenDirectoryCheck.NotPrivate;
        }

        if ((directory.Mode & GroupOrOtherRead) != 0)
        {
            warnings.WriteLine(
                "WARNING: the token directory is readable by others than its owner. Only a Linux host file system keeps it 0700 (docs/install.md).");
        }

        var token = Native.Status(PublishedPath);
        if (token.Exists && !token.IsRegular)
        {
            return TokenDirectoryCheck.TokenNotRegular;
        }

        try
        {
            Sweep();

            var probe = TemporaryPath("probe");
            using (Create(probe))
            {
            }

            File.Delete(probe);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return TokenDirectoryCheck.NotWritable;
        }

        return TokenDirectoryCheck.Ready;
    }

    /// <summary>Writes the token and a newline, synced, to a new file that isn't yet the token file.</summary>
    public async Task StageAsync(byte[] token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (_staged is not null)
        {
            throw new InvalidOperationException("A token is already staged.");
        }

        var path = TemporaryPath("tmp");
        _staged = path;

        await using var stream = Create(path);
        await stream.WriteAsync(token, cancellationToken);
        await stream.WriteAsync("\n"u8.ToArray(), cancellationToken);
        stream.Flush(flushToDisk: true);
    }

    /// <summary>
    /// Keeps the current token file as a hard link, then renames the staged file over it,
    /// atomically on one file system, and syncs the directory.
    /// </summary>
    public void Publish()
    {
        var staged = _staged ?? throw new InvalidOperationException("No token is staged.");

        if (Native.Status(PublishedPath).IsRegular)
        {
            var previous = TemporaryPath("prev");
            Native.HardLink(PublishedPath, previous);
            _previous = previous;
        }

        File.Move(staged, PublishedPath, overwrite: true);
        _staged = null;
        _published = true;
        Native.SyncDirectory(_directory);
    }

    /// <summary>The row is committed: the previous token is void, so its link goes.</summary>
    public void Complete()
    {
        if (_previous is { } previous)
        {
            File.Delete(previous);
            _previous = null;
            Native.SyncDirectory(_directory);
        }
    }

    /// <summary>
    /// The row wasn't committed, or may not have been: the previous token file goes back, or,
    /// when there was none, the published one goes. False when that failed.
    /// </summary>
    public bool Restore()
    {
        if (!_published)
        {
            return true;
        }

        try
        {
            if (_previous is { } previous)
            {
                File.Move(previous, PublishedPath, overwrite: true);
                _previous = null;
            }
            else
            {
                File.Delete(PublishedPath);
            }

            _published = false;
            Native.SyncDirectory(_directory);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (_staged is { } staged)
        {
            TryDelete(staged);
            _staged = null;
        }
    }

    /// <summary>
    /// Removes temporary and probe files a dead run left, and its previous-token link: back in
    /// place when no token file is left, otherwise deleted.
    /// </summary>
    private void Sweep()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var path in Directory.EnumerateFiles(_directory, Prefix + "*"))
        {
            var status = Native.Status(path);
            var previous = path.EndsWith(".prev", StringComparison.Ordinal);

            // A temporary file is written once, so its write time is its age. A previous-token
            // link keeps the old token's write time, so its age is the link's, its change time.
            var age = now - (previous ? status.Changed : File.GetLastWriteTimeUtc(path));
            if (!status.Exists || status.IsSymbolicLink || age < StaleAfter)
            {
                continue;
            }

            if (previous && !Native.Status(PublishedPath).Exists)
            {
                File.Move(path, PublishedPath, overwrite: false);
            }
            else if (path.EndsWith(".tmp", StringComparison.Ordinal)
                || path.EndsWith(".probe", StringComparison.Ordinal)
                || path.EndsWith(".prev", StringComparison.Ordinal))
            {
                File.Delete(path);
            }
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Best effort: the file holds a token whose hash was never committed.
        }
    }

    private string TemporaryPath(string suffix) =>
        Path.Combine(_directory, $"{Prefix}{Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8))}.{suffix}");

    /// <summary>A new file, never an existing one, owner read and write only from the moment it exists.</summary>
    private static FileStream Create(string path)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
        };

        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        return new FileStream(path, options);
    }
}
