using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Authentication.Contracts;

/// <summary>A sign-in Protocol asks for: the Application it is for and its authorization parameters.</summary>
public sealed record SignInRequest(Guid ApplicationId, IReadOnlyDictionary<string, string> Parameters);

/// <summary>
/// A begun sign-in. <paramref name="Binding"/> is the <c>__Host-gk_txn</c> value: base64url of
/// 32 random bytes. Only its SHA-256 is stored, so it can't be read back.
/// </summary>
public sealed record StartedSignIn(Guid TransactionId, Secret<string> Binding);

/// <summary>Sign-in (AD-8, AD-12). Authentication owns <c>signin_transaction</c>.</summary>
public interface IAuthentication
{
    /// <summary>
    /// Writes a <c>signin_transaction</c> row bound to a new browser value, the context's
    /// Tenant and the Application, and one <c>authentication.signin_transaction.started</c>
    /// audit event, both in the caller's context. It expires after the §5.2 sliding lifetime.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    /// <exception cref="ArgumentException">
    /// The Application ID is empty, a parameter is null or holds a NUL character, or the
    /// parameters exceed 16 KiB as JSON. Nothing is written.
    /// </exception>
    [StateChanging]
    Task<StartedSignIn> BeginAsync(CommandContext context, SignInRequest request, CancellationToken cancellationToken);
}
