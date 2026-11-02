using Npgsql;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// A job connection that connects as another role. It's a configuration error, never
/// transient, so the runner and the schedule let it escape and the host stops.
/// </summary>
internal sealed class WrongJobRoleException(string role)
    : InvalidOperationException($"The job database for {role} connects as another role.");

internal static class RoleCheck
{
    /// <exception cref="WrongJobRoleException">The connection's role isn't <paramref name="role"/>.</exception>
    public static async Task EnsureAsync(NpgsqlDataSource source, string role, CancellationToken cancellationToken)
    {
        await using var command = source.CreateCommand("SELECT current_user::text");
        var actual = (string?)await command.ExecuteScalarAsync(cancellationToken);

        if (actual != role)
        {
            throw new WrongJobRoleException(role);
        }
    }
}
