namespace Gatekeep.Adapters.OpenBao;

/// <summary>
/// Where OpenBao is and how this host logs in. The role ID and secret ID are read from
/// files at each login, never held in configuration (Story 1.10 delivers them).
/// </summary>
public sealed record OpenBaoOptions
{
    /// <summary>The production path: OpenBao's unix socket. Set this or <see cref="Address"/>.</summary>
    public string? SocketPath { get; init; }

    /// <summary>An HTTP address, used only by tests that can't reach a unix socket.</summary>
    public Uri? Address { get; init; }

    public required string RoleIdFile { get; init; }

    public required string SecretIdFile { get; init; }

    /// <summary>The AppRole mount. Setup creates it at <c>approle</c>.</summary>
    public string AuthMount { get; init; } = "approle";

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    internal void Validate()
    {
        if ((SocketPath is null) == (Address is null))
        {
            throw new ArgumentException("Set exactly one of SocketPath or Address.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(RoleIdFile);
        ArgumentException.ThrowIfNullOrWhiteSpace(SecretIdFile);
        ArgumentException.ThrowIfNullOrWhiteSpace(AuthMount);
    }
}
