namespace Gatekeep.Kernel.Alerts;

/// <summary>
/// The way out for Security Alerts (AD-17): a service outside the Deployment, chosen at install.
/// A send either reaches it, answered 2xx, or throws <see cref="AlertChannelException"/>. It is
/// never retried inside the channel: the caller decides, as Story 11.1's alert jobs will.
/// </summary>
public interface IAlertChannel
{
    Task SendAsync(SecurityAlert alert, CancellationToken cancellationToken);
}
