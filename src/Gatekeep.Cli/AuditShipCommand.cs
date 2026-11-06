using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Gatekeep.Adapters.Egress;
using Gatekeep.Adapters.ObjectLock;
using Gatekeep.Kernel.Records;

namespace Gatekeep.Cli;

/// <summary>
/// Copies what OpenBao appends to its audit file into the off-server bucket (Story 1.30, AD-10),
/// in whole lines, as objects <c>openbao-audit/{yyyy}/{MM}/{dd}/{fileId}-{startOffset:D20}.jsonl</c>.
/// Its read offset lives in its own state directory, saved only after a chunk is written, so a
/// restart resumes with no gap. The state also holds a hash of the file's first shipped bytes: a
/// file shorter than the saved offset, or whose start no longer matches, was replaced or truncated,
/// so shipping starts over from 0 under a new file ID and no key repeats. The chunks aren't signed:
/// Object Lock keeps them from erasure (the spec's Design Notes).
/// </summary>
public sealed class AuditShipper(IOffServerStore store, string auditFile, string stateDirectory, TimeProvider time, TextWriter output)
{
    /// <summary>
    /// The most one object holds: small enough to go up well inside the store's 10-second timeout
    /// on a slow link. A longer line is split, which no audit record reaches.
    /// </summary>
    public const int MaxChunkBytes = 1024 * 1024;

    /// <summary>How much of the file's start identifies it: once shipped, those bytes never change unless the file is replaced.</summary>
    public const int IdentityBytes = 4096;

    public const string ContentType = "application/x-ndjson";

    public const string Shrunk = "The audit file is shorter than what was shipped, so shipping starts over from its beginning under a new file ID.";
    public const string Replaced = "The audit file was replaced, so shipping starts over from its beginning under a new file ID.";
    public const string StateUnreadable = "The shipper's saved state can't be read, so shipping starts over from the audit file's beginning under a new file ID.";

    private const string StateFile = "state";

    /// <summary>The object key for the chunk of file <paramref name="fileId"/> starting at <paramref name="startOffset"/>, shipped at <paramref name="shippedAt"/>.</summary>
    public static string ObjectKey(Guid fileId, long startOffset, DateTimeOffset shippedAt)
    {
        var day = shippedAt.UtcDateTime;
        return string.Create(
            CultureInfo.InvariantCulture,
            $"openbao-audit/{day:yyyy}/{day:MM}/{day:dd}/{fileId:D}-{startOffset:D20}.jsonl");
    }

    /// <summary>
    /// Ships every whole line appended since the saved offset. Returns the bytes shipped, or null
    /// when the audit file doesn't exist yet. A store failure throws <see cref="OffServerStoreException"/>
    /// with the offset left at the last chunk written.
    /// </summary>
    public async Task<long?> ShipAsync(CancellationToken cancellationToken)
    {
        FileStream file;
        try
        {
            file = new FileStream(auditFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }

        await using (file)
        {
            var state = await LoadAsync();
            var length = file.Length;
            if (length < state.Offset)
            {
                state = await StartOverAsync(Shrunk);
            }
            else if (state.Offset > 0 && !await StartMatchesAsync(file, state, cancellationToken))
            {
                state = await StartOverAsync(Replaced);
            }

            long shipped = 0;
            var buffer = new byte[MaxChunkBytes];
            while (state.Offset < length)
            {
                var want = (int)Math.Min(MaxChunkBytes, length - state.Offset);
                file.Seek(state.Offset, SeekOrigin.Begin);
                await file.ReadExactlyAsync(buffer.AsMemory(0, want), cancellationToken);

                // Whole lines only: OpenBao may be part way through writing the last one.
                var end = Array.LastIndexOf(buffer, (byte)'\n', want - 1) + 1;
                if (end == 0)
                {
                    if (want < MaxChunkBytes)
                    {
                        break;
                    }

                    end = want;
                }

                var key = ObjectKey(state.FileId, state.Offset, time.GetUtcNow());
                await store.PutAsync(key, buffer.AsMemory(0, end), ContentType, cancellationToken);

                var offset = state.Offset + end;
                var start = state.Offset < IdentityBytes ? await StartHashAsync(file, offset, cancellationToken) : state.StartHash;
                state = state with { Offset = offset, StartHash = start };
                Save(state);
                shipped += end;
                await output.WriteLineAsync(string.Create(CultureInfo.InvariantCulture, $"Shipped {end} bytes of the audit file as {key}."));
            }

            return shipped;
        }

        async Task<ShipState> StartOverAsync(string reason)
        {
            var fresh = Fresh();
            Save(fresh);
            await output.WriteLineAsync(reason);
            return fresh;
        }
    }

    /// <summary>The SHA-256 of the file's first <see cref="IdentityBytes"/> bytes, or fewer when fewer were shipped up to <paramref name="offset"/>.</summary>
    private static async Task<string> StartHashAsync(FileStream file, long offset, CancellationToken cancellationToken)
    {
        var start = new byte[(int)Math.Min(IdentityBytes, offset)];
        file.Seek(0, SeekOrigin.Begin);
        await file.ReadExactlyAsync(start, cancellationToken);
        return Convert.ToHexStringLower(SHA256.HashData(start));
    }

    private static async Task<bool> StartMatchesAsync(FileStream file, ShipState state, CancellationToken cancellationToken) =>
        string.Equals(await StartHashAsync(file, state.Offset, cancellationToken), state.StartHash, StringComparison.Ordinal);

    /// <summary>
    /// The saved file ID, offset and start hash. None saved yet is a fresh file ID at 0. One that
    /// can't be parsed says so, then starts over the same way, which ships everything again rather
    /// than leave a gap.
    /// </summary>
    private async Task<ShipState> LoadAsync()
    {
        var path = Path.Combine(stateDirectory, StateFile);
        string[] lines;
        try
        {
            lines = File.ReadAllLines(path);
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            var fresh = Fresh();
            Save(fresh);
            return fresh;
        }

        if (lines.Length == 3
            && Guid.TryParseExact(lines[0], "D", out var fileId)
            && long.TryParse(lines[1], NumberStyles.None, CultureInfo.InvariantCulture, out var offset)
            && lines[2].Length == 2 * SHA256.HashSizeInBytes
            && lines[2].All(char.IsAsciiHexDigitLower))
        {
            return new ShipState(fileId, offset, lines[2]);
        }

        var restarted = Fresh();
        Save(restarted);
        await output.WriteLineAsync(StateUnreadable);
        return restarted;
    }

    private ShipState Fresh() => new(Guid.CreateVersion7(time.GetUtcNow()), 0, Convert.ToHexStringLower(SHA256.HashData([])));

    /// <summary>Written beside, then moved over, so a crash leaves the old state or the new, never half.</summary>
    private void Save(ShipState state)
    {
        var path = Path.Combine(stateDirectory, StateFile);
        var temporary = path + ".new";
        File.WriteAllText(temporary, string.Create(CultureInfo.InvariantCulture, $"{state.FileId:D}\n{state.Offset}\n{state.StartHash}\n"));
        File.Move(temporary, path, overwrite: true);
    }

    private sealed record ShipState(Guid FileId, long Offset, string StartHash);
}

/// <summary>
/// <c>gatekeep audit-ship [--once]</c> (Story 1.30): the <c>openbao-audit-shipper</c> Compose service.
/// It reads OpenBao's audit file read-only and ships what is appended every few seconds, well within
/// 30 seconds of a write, until stopped; <c>--once</c> ships what is there and exits. It refuses
/// before reading anything when a setting is missing or unsafe, and prints only fixed lines, counts
/// and object keys: never a byte of the file, the address, the bucket or the credential.
/// </summary>
public static class AuditShipCommand
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(5);

    public const string Unavailable = "Off-server store unavailable: the audit file wasn't shipped. It will be tried again.";
    public const string Rejected = "Off-server store rejected an audit chunk: it wasn't shipped. It will be tried again.";
    public const string RefusedPrivate = "Off-server store refused: private address. The audit file wasn't shipped.";
    public const string RefusedCredential = "Off-server store refused: credential file unusable. The audit file wasn't shipped.";
    public const string Unreadable = "Can't read the audit file or the shipper's state. Nothing more was shipped.";

    private const int Success = 0;
    private const int Failure = 1;

    public static async Task<int> RunAsync(bool once)
    {
        var refused = new List<string>();
        var records = OffServerSettings.Records(Environment.GetEnvironmentVariable, refused);

        var auditFile = Environment.GetEnvironmentVariable(OffServerSettings.AuditLogFileVariable);
        if (string.IsNullOrWhiteSpace(auditFile))
        {
            refused.Add(OffServerSettings.AuditLogFileVariable);
        }

        var stateDirectory = Environment.GetEnvironmentVariable(OffServerSettings.AuditShipStateVariable);
        // Refused unless it takes a file, before anything is shipped: a save that fails after a write
        // would write the same chunk again on every pass.
        if (!OffServerSettings.IsWritableDirectory(stateDirectory))
        {
            refused.Add(OffServerSettings.AuditShipStateVariable);
        }

        if (records is null || refused.Count > 0)
        {
            await Console.Error.WriteLineAsync(OffServerSettings.Refusal(refused, "Nothing was shipped."));
            return Failure;
        }

        using var cancellation = new CancellationTokenSource();
        using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, Cancel);
        using var terminate = PosixSignalRegistration.Create(PosixSignal.SIGTERM, Cancel);

        void Cancel(PosixSignalContext context)
        {
            context.Cancel = true;
            cancellation.Cancel();
        }

        return await ShipAsync(
            records, auditFile!, stateDirectory!, EgressHttp.Create(), TimeProvider.System, Console.Out, Console.Error, once, Interval, cancellation.Token);
    }

    /// <summary>The shipping itself, with the handler given: <see cref="EgressHttp"/>'s, or the isolation tests' permit.</summary>
    public static async Task<int> ShipAsync(
        ObjectLockOptions options,
        string auditFile,
        string stateDirectory,
        HttpMessageHandler handler,
        TimeProvider time,
        TextWriter output,
        TextWriter error,
        bool once,
        TimeSpan interval,
        CancellationToken cancellationToken)
    {
        using var store = new S3ObjectLockStore(handler, options, time);
        var shipper = new AuditShipper(store, auditFile, stateDirectory, time, output);

        if (!once)
        {
            await output.WriteLineAsync(string.Create(
                CultureInfo.InvariantCulture, $"Shipping the audit file every {interval.TotalSeconds:0} seconds."));
        }

        // A failure is said once, not on every pass, until a pass succeeds again.
        string? lastFailure = null;
        while (true)
        {
            string? failure;
            try
            {
                var shipped = await shipper.ShipAsync(cancellationToken);
                failure = null;
                if (once)
                {
                    await output.WriteLineAsync(shipped is null
                        ? "There is no audit file yet. Nothing was shipped."
                        : string.Create(CultureInfo.InvariantCulture, $"Shipped {shipped} bytes of the audit file."));
                }
            }
            catch (OffServerStoreException e)
            {
                failure = e.Failure switch
                {
                    OffServerStoreFailure.Rejected => Rejected,
                    OffServerStoreFailure.Unavailable => Unavailable,
                    _ when e.Refusal == OffServerRefusal.CredentialFile => RefusedCredential,
                    _ => RefusedPrivate,
                };
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                failure = Unreadable;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return Success;
            }

            if (failure is not null && failure != lastFailure)
            {
                await error.WriteLineAsync(failure);
            }

            lastFailure = failure;
            if (once)
            {
                return failure is null ? Success : Failure;
            }

            try
            {
                await Task.Delay(interval, time, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return Success;
            }
        }
    }
}
