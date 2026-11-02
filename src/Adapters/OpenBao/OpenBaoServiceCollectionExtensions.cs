using Gatekeep.Kernel.Secrets;
using Microsoft.Extensions.DependencyInjection;

namespace Gatekeep.Adapters.OpenBao;

public static class OpenBaoServiceCollectionExtensions
{
    /// <summary>
    /// Registers OpenBao as this host's <see cref="IKeyCustody"/>. The shared host startup
    /// (Story 1.10) calls it with the socket path and the host's AppRole files.
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
