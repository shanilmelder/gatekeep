using System.Diagnostics;
using System.Reflection;
using Gatekeep.Adapters.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Gatekeep.Tests.Isolation.Scrubbing;

/// <summary>
/// Runs each host's real entry point and reads the service provider it builds. Hosts are
/// loaded from their output folders, so the edge list stays the real dependency graph.
/// </summary>
public sealed class HostLoggingTests
{
    private const string HostingListener = "Microsoft.Extensions.Hosting";
    private const string HostBuilt = "HostBuilt";

    private static readonly TimeSpan HostTimeout = TimeSpan.FromSeconds(30);

    [Theory]
    [InlineData("Gatekeep.Host.Hosted")]
    [InlineData("Gatekeep.Host.Admin")]
    [InlineData("Gatekeep.Host.Worker")]
    public async Task Scrubbing_provider_is_the_only_one(string host)
    {
        var providers = await ProviderTypesAsync(host);

        Assert.Equal(typeof(ScrubbingLoggerProvider), Assert.Single(providers));
    }

    private static async Task<List<Type>> ProviderTypesAsync(string host)
    {
        var entryPoint = Assembly.LoadFrom(BuildOutput.AssemblyPath(host, host)).EntryPoint!;
        var capture = new ProviderCapture();

        using (DiagnosticListener.AllListeners.Subscribe(capture))
        {
            var cancellation = TestContext.Current.CancellationToken;
            var run = Task.Run(
                () =>
                {
                    // Only this host's build is stopped: other tests build hosts in this process too.
                    ProviderCapture.Capturing.Value = true;
                    return entryPoint.Invoke(null, [Array.Empty<string>()]);
                },
                cancellation);

            var stopped = await Assert.ThrowsAsync<TargetInvocationException>(
                () => run.WaitAsync(HostTimeout, cancellation));

            Assert.IsType<HostStopped>(stopped.InnerException);
        }

        return capture.ProviderTypes;
    }

    /// <summary>Thrown out of the host's build, so it reads the provider and never serves.</summary>
    private sealed class HostStopped : Exception;

    private sealed class ProviderCapture : IObserver<DiagnosticListener>, IObserver<KeyValuePair<string, object?>>
    {
        /// <summary>Set on the flow that runs the host under test, so a host another test builds meanwhile is left alone.</summary>
        public static readonly AsyncLocal<bool> Capturing = new();

        public List<Type> ProviderTypes { get; } = [];

        public void OnNext(DiagnosticListener value)
        {
            if (value.Name == HostingListener)
            {
                value.Subscribe(this);
            }
        }

        public void OnNext(KeyValuePair<string, object?> value)
        {
            if (value.Key != HostBuilt || !Capturing.Value)
            {
                return;
            }

            using var host = (IHost)value.Value!;
            ProviderTypes.AddRange(host.Services.GetServices<ILoggerProvider>().Select(p => p.GetType()));
            throw new HostStopped();
        }

        public void OnCompleted()
        {
        }

        public void OnError(Exception error)
        {
        }
    }
}
