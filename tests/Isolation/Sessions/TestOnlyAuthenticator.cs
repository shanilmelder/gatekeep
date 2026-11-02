using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Sessions.Contracts;

namespace Gatekeep.Tests.Isolation.Sessions;

/// <summary>
/// Completes a begun sign-in with no real factor: it trusts the User ID it's given and starts
/// a Session for it. Test only. Nothing under <c>src/</c> may return an
/// <see cref="AuthenticationResult"/> this way, and a test checks this type stays here.
/// </summary>
internal sealed class TestOnlyAuthenticator(ISessions sessions, TimeProvider time)
{
    public const string Method = "test";

    /// <summary>
    /// Starts a Session for <paramref name="userId"/> once the transaction is found, unexpired,
    /// in the context's Tenant.
    /// </summary>
    /// <exception cref="InvalidOperationException">No such unexpired transaction is visible in the context.</exception>
    public async Task<(AuthenticationResult Result, StartedSession Session)> AuthenticateAsync(
        CommandContext context,
        Guid transactionId,
        Guid userId,
        DateTimeOffset authTime,
        CancellationToken cancellationToken)
    {
        await using (var command = context.CreateCommand())
        {
            command.CommandText = "SELECT count(*) FROM signin_transaction WHERE id = @id AND expires_at > @now";
            Add(command, "id", transactionId);
            Add(command, "now", time.GetUtcNow());

            if ((long)(await command.ExecuteScalarAsync(cancellationToken))! != 1)
            {
                throw new InvalidOperationException("No such unexpired sign-in transaction in this Tenant.");
            }
        }

        string[] amr = [Method];
        var session = await sessions.StartAsync(context, new NewSession(userId, amr, authTime), cancellationToken);

        // The stored auth_time, truncated to microseconds, not the one passed in.
        return (new AuthenticationResult(session.SessionId, userId, amr, session.AuthTime), session);
    }

    private static void Add(System.Data.Common.DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}
