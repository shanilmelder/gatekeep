using System.Runtime.InteropServices;

namespace Gatekeep.Cli;

/// <summary>What one <c>statx</c> call without following links says about a path.</summary>
internal readonly record struct PathStatus(bool Exists, uint Type, uint Mode, uint Uid, uint Gid, DateTimeOffset Changed, ulong Inode)
{
    public const uint TypeMask = 0xF000;
    public const uint Directory = 0x4000;
    public const uint Regular = 0x8000;
    public const uint SymbolicLink = 0xA000;

    public bool IsDirectory => Type == Directory;

    public bool IsRegular => Type == Regular;

    public bool IsSymbolicLink => Type == SymbolicLink;
}

/// <summary>
/// The few Linux calls .NET doesn't offer (Story 1.19): <c>lstat</c> as <c>statx</c>, whose
/// layout is the same on every architecture, a hard link, a directory <c>fsync</c>, and this
/// process's effective IDs. The Cli runs only in its Linux container.
/// </summary>
internal static class Native
{
    private const int AtFdCwd = -100;
    private const int AtSymlinkNoFollow = 0x100;

    // STATX_TYPE | STATX_MODE | STATX_UID | STATX_GID | STATX_INO | STATX_CTIME.
    private const uint StatxMask = 0x1 | 0x2 | 0x8 | 0x10 | 0x100 | 0x80;
    private const int StatxSize = 256;
    private const int ENOENT = 2;

    private const int ReadOnly = 0;
    private const int CloseOnExec = 0x80000;

    public static PathStatus Status(string path)
    {
        var buffer = new byte[StatxSize];
        if (statx(AtFdCwd, path, AtSymlinkNoFollow, StatxMask, buffer) != 0)
        {
            var error = Marshal.GetLastPInvokeError();
            return error == ENOENT
                ? default
                : throw new IOException($"Can't read the status of a path (errno {error}).");
        }

        // struct statx: stx_uid at 20, stx_gid at 24, stx_mode at 28, stx_ino at 32, stx_ctime at 96.
        var uid = BitConverter.ToUInt32(buffer, 20);
        var gid = BitConverter.ToUInt32(buffer, 24);
        var mode = (uint)BitConverter.ToUInt16(buffer, 28);
        var inode = BitConverter.ToUInt64(buffer, 32);
        var changed = DateTimeOffset.FromUnixTimeSeconds(BitConverter.ToInt64(buffer, 96));

        return new PathStatus(true, mode & PathStatus.TypeMask, mode & 0xFFF, uid, gid, changed, inode);
    }

    public static uint EffectiveUid => geteuid();

    /// <summary>A second name for <paramref name="existing"/>, refused when <paramref name="link"/> exists.</summary>
    public static void HardLink(string existing, string link)
    {
        if (Native.link(existing, link) != 0)
        {
            throw new IOException($"Can't link the token file (errno {Marshal.GetLastPInvokeError()}).");
        }
    }

    /// <summary>Makes a rename or unlink in <paramref name="directory"/> durable.</summary>
    public static void SyncDirectory(string directory)
    {
        // O_DIRECTORY differs by architecture.
        var flags = ReadOnly | CloseOnExec
            | (RuntimeInformation.ProcessArchitecture is Architecture.Arm64 or Architecture.Arm ? 0x4000 : 0x10000);

        var descriptor = open(directory, flags);
        if (descriptor < 0)
        {
            throw new IOException($"Can't open the token directory to sync it (errno {Marshal.GetLastPInvokeError()}).");
        }

        try
        {
            if (fsync(descriptor) != 0)
            {
                throw new IOException($"Can't sync the token directory (errno {Marshal.GetLastPInvokeError()}).");
            }
        }
        finally
        {
            _ = close(descriptor);
        }
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int statx(
        int dirfd,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string pathname,
        int flags,
        uint mask,
        [Out] byte[] statxbuf);

    [DllImport("libc", SetLastError = true)]
    private static extern int link(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string oldpath,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string newpath);

    [DllImport("libc", SetLastError = true)]
    private static extern int open([MarshalAs(UnmanagedType.LPUTF8Str)] string pathname, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int fsync(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc")]
    private static extern uint geteuid();
}
