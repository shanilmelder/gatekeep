using Gatekeep.Kernel.Secrets;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeep.Adapters.OpenBao;

public static class OpenBaoServiceCollectionExtensions
{
    /// <summary>
    /// Registers OpenBao as this host's <see cref="IKeyCustody"/>. No host calls this yet:
    /// Story 1.10 wires hosts and delivers their secret IDs.
    /// </summary>
    public static IServiceCollection AddOpenBaoKeyCustody(this IServiceCollection services, OpenBaoOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        services.AddSingleton<IKeyCustody>(provider =>
            new OpenBaoKeyCustody(options, provider.GetService<TimeProvider>() ?? TimeProvider.System));

        return services;
    }
}
