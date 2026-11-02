using System.Net;
using System.Text;

namespace Gatekeep.Tests.Isolation.Custody;

/// <summary>A clock that never moves, so the adapter never renews a token on its own.</summary>
internal sealed class FrozenTime : TimeProvider
{
    private readonly DateTimeOffset _now = DateTimeOffset.UtcNow;

    public override DateTimeOffset GetUtcNow() => _now;
}

/// <summary>Records the path of every request the adapter sends.</summary>
internal sealed class CountingHandler
{
    private readonly List<string> _paths = [];
    private readonly Lock _lock = new();

    public HttpMessageHandler Wrap(HttpMessageHandler inner) => new Counting(this, inner);

    public int Count(string fragment)
    {
        lock (_lock)
        {
            return _paths.Count(p => p.Contains(fragment, StringComparison.Ordinal));
        }
    }

    private sealed class Counting(CountingHandler owner, HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            lock (owner._lock)
            {
                owner._paths.Add(request.RequestUri!.AbsolutePath);
            }

            return base.SendAsync(request, cancellationToken);
        }
    }
}

/// <summary>Answers login with a token, and every other request with a fixed status and body.</summary>
internal sealed class StubOpenBao(
    HttpStatusCode status,
    string body = "{}",
    HttpStatusCode loginStatus = HttpStatusCode.OK) : HttpMessageHandler
{
    private const string Login = """{"auth":{"client_token":"stub-token","lease_duration":900}}""";

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var isLogin = request.RequestUri!.AbsolutePath.EndsWith("/login", StringComparison.Ordinal);
        var (code, text) = isLogin ? (loginStatus, loginStatus == HttpStatusCode.OK ? Login : "{}") : (status, body);

        return Task.FromResult(new HttpResponseMessage(code)
        {
            Content = new StringContent(text, Encoding.UTF8, "application/json"),
        });
    }
}
