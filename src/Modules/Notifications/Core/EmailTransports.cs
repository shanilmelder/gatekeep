using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Email;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Notifications.Contracts;

namespace Gatekeep.Modules.Notifications.Core;

/// <summary>
/// Turns a stored provider into the Kernel transport the email port sends through (Story 4.5, AD-10): its settings as
/// stored, and its secret decrypted at the moment of use under the Tenant's <c>email-</c> key, with the Tenant ID as
/// associated data, so a ciphertext of another Tenant is rejected. Only Host.Worker's custody may decrypt there.
/// </summary>
internal static class EmailTransports
{
    /// <exception cref="KeyCustodyException">Custody refused, rejected or failed the decrypt.</exception>
    public static async Task<EmailTransport> CreateAsync(
        EmailDelivery delivery,
        Guid tenantId,
        IKeyCustody custody,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(delivery);
        ArgumentNullException.ThrowIfNull(custody);
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("A Tenant's provider is decrypted for that Tenant.", nameof(tenantId));
        }

        Secret<string>? secret = null;
        if (delivery.SecretCiphertext is { } ciphertext)
        {
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(SecurityLimits.KeyCustodyCallTimeout);
            var plaintext = await custody
                .DecryptAsync(KeyName.ForTenant(TenantKeyClass.Email, tenantId), tenantId, new KeyCiphertext(ciphertext), limit.Token)
                .WaitAsync(limit.Token);
            secret = plaintext.Use(bytes =>
            {
                try
                {
                    return new Secret<string>(Encoding.UTF8.GetString(bytes));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            });
        }

        var settings = delivery.Provider.Settings;
        return new EmailTransport
        {
            Kind = delivery.Provider.Kind,
            Host = settings.Host,
            Port = settings.Port,
            Tls = settings.Tls,
            Username = settings.Username,
            Region = settings.Region,
            MessageStream = settings.MessageStream,
            Domain = settings.Domain,
            AccessKeyId = settings.AccessKeyId,
            Endpoint = settings.Endpoint,
            AuthHeaderName = settings.AuthHeaderName,
            Secret = secret,
        };
    }
}
