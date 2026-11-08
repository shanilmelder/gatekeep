using System.Net;
using Gatekeep.Adapters.Egress;
using Xunit;

namespace Gatekeep.Tests.Isolation.OffServer;

/// <summary>
/// Story 1.30: the one outbound path. It refuses every private, loopback, link-local, reserved and
/// embedded-private address, resolves names itself and connects only to what it checked, sends no
/// plain HTTP, follows no redirect, keeps no cookie and uses no proxy. A refusal names the host,
/// never the addresses.
/// </summary>
public sealed class EgressHttpTests
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("0.1.2.3")]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.255")]
    [InlineData("100.64.0.1")]
    [InlineData("100.127.255.254")]
    [InlineData("127.0.0.1")]
    [InlineData("127.255.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.0.0.8")]
    [InlineData("192.0.2.1")]
    [InlineData("192.168.65.254")]
    [InlineData("198.18.0.1")]
    [InlineData("198.19.255.255")]
    [InlineData("198.51.100.7")]
    [InlineData("203.0.113.9")]
    [InlineData("224.0.0.1")]
    [InlineData("239.255.255.250")]
    [InlineData("240.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("fc00::1")]
    [InlineData("fd00::1")]
    [InlineData("fdc4:f303:9324::254")]
    [InlineData("fe80::1")]
    [InlineData("fe80::1%2")]
    [InlineData("febf::1")]
    [InlineData("ff02::1")]
    [InlineData("2001:db8::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:192.168.1.1")]
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::127.0.0.1")]
    [InlineData("64:ff9b::10.0.0.1")]
    [InlineData("64:ff9b::a9fe:a9fe")]
    [InlineData("2002:c0a8:0101::1")]
    [InlineData("2002:7f00:0001::1")]
    [InlineData("192.88.99.1")]
    [InlineData("64:ff9b:1::808:808")]
    [InlineData("fec0::1")]
    [InlineData("feff::1")]
    [InlineData("100::1")]
    [InlineData("2001::808:808")]
    [InlineData("2001:0:4136:e378:8000:63bf:3fff:fdd2")]
    [InlineData("2001:10::1")]
    [InlineData("2001:1f::1")]
    [InlineData("2001:20::1")]
    [InlineData("2001:2f::1")]
    [InlineData("3fff::1")]
    [InlineData("3fff:fff::1")]
    [InlineData("::ffff:0:808:808")]
    [InlineData("::ffff:0:10.0.0.1")]
    public void Address_is_refused(string address)
    {
        Assert.True(EgressAddresses.IsRefused(IPAddress.Parse(address)), $"{address} is allowed.");
    }

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("100.63.255.255")]
    [InlineData("100.128.0.1")]
    [InlineData("172.15.255.255")]
    [InlineData("172.32.0.1")]
    [InlineData("192.0.1.1")]
    [InlineData("192.169.0.1")]
    [InlineData("198.17.255.255")]
    [InlineData("198.20.0.1")]
    [InlineData("223.255.255.255")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("::ffff:1.1.1.1")]
    [InlineData("64:ff9b::808:808")]
    [InlineData("2002:0808:0808::1")]
    [InlineData("192.88.98.1")]
    [InlineData("192.88.100.1")]
    [InlineData("100:0:0:1::1")]
    [InlineData("2001:1::1")]
    [InlineData("2001:30::1")]
    [InlineData("3fff:1000::1")]
    public void Public_address_is_allowed(string address)
    {
        Assert.False(EgressAddresses.IsRefused(IPAddress.Parse(address)), $"{address} is refused.");
    }

    [Theory]
    [InlineData("https://10.0.0.1/", "10.0.0.1")]
    [InlineData("https://127.0.0.1:9/", "127.0.0.1")]
    [InlineData("https://[::1]/", "[::1]")]
    [InlineData("https://[::ffff:192.168.1.1]/", "[::ffff:192.168.1.1]")]
    [InlineData("https://localhost/", "localhost")]
    [InlineData("https://host.docker.internal/", "host.docker.internal")]
    public async Task Private_target_is_refused_before_any_connection_naming_the_host_only(string url, string host)
    {
        using var http = new HttpClient(EgressHttp.Create());

        var failure = await Assert.ThrowsAsync<HttpRequestException>(() => http.GetAsync(url, Cancellation));

        var refused = EgressRefusedException.Find(failure);
        Assert.NotNull(refused);
        Assert.Equal(EgressRefusal.PrivateAddress, refused.Reason);
        Assert.Contains(host.Trim('[', ']'), refused.Host.Trim('[', ']'), StringComparison.Ordinal);
        if (host is "localhost" or "host.docker.internal")
        {
            // The addresses the name resolved to are no part of the refusal.
            Assert.DoesNotContain("127.0.0.1", refused.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("::1", refused.Message, StringComparison.Ordinal);
            Assert.DoesNotMatch(@"\b(?:10|172|192)\.\d+\.\d+\.\d+\b", refused.Message);
        }
    }

    [Fact]
    public async Task Plain_HTTP_is_refused_even_to_a_listening_loopback_without_the_test_permit()
    {
        await using var sink = await AlertSinkFixture.StartAsync();
        using var http = new HttpClient(EgressHttp.Create());

        var failure = await Assert.ThrowsAsync<HttpRequestException>(() => http.GetAsync(sink.Url, Cancellation));

        Assert.Equal(EgressRefusal.PlainHttp, EgressRefusedException.Find(failure)!.Reason);
        Assert.Empty(sink.Requests);
    }

    [Fact]
    public async Task Test_permit_reaches_the_loopback_sink_and_still_follows_no_redirect()
    {
        await using var sink = await AlertSinkFixture.StartAsync();
        sink.Status = 302;
        sink.Location = sink.Url.ToString();
        using var http = new HttpClient(ObjectLockFixture.Permitted());

        using var response = await http.GetAsync(sink.Url, Cancellation);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Single(sink.Requests);
    }

    [Fact]
    public async Task Name_resolving_to_private_and_public_addresses_dials_only_the_public_ones_IPv4_first()
    {
        var dialled = new List<IPAddress>();
        using var http = new HttpClient(EgressHttp.Create(
            EgressPermit.None,
            resolve: (_, _) => Task.FromResult(new[]
            {
                IPAddress.Parse("10.0.0.1"),
                IPAddress.Parse("2606:4700:4700::1111"),
                IPAddress.Parse("127.0.0.1"),
                IPAddress.Parse("1.1.1.1"),
                IPAddress.Parse("fd00::1"),
            }),
            connect: (target, _) =>
            {
                dialled.Add(target.Address);
                throw new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.ConnectionRefused);
            }));

        await Assert.ThrowsAsync<HttpRequestException>(() => http.GetAsync("https://rebinding.example/", Cancellation));

        // The name is looked up once, by the handler, and only what passed the check is dialled.
        Assert.Equal([IPAddress.Parse("1.1.1.1"), IPAddress.Parse("2606:4700:4700::1111")], dialled);
    }

    [Fact]
    public async Task Name_resolving_only_to_private_addresses_is_refused_and_nothing_is_dialled()
    {
        var dialled = 0;
        using var http = new HttpClient(EgressHttp.Create(
            EgressPermit.None,
            resolve: (_, _) => Task.FromResult(new[] { IPAddress.Parse("10.0.0.1"), IPAddress.Parse("::ffff:169.254.169.254") }),
            connect: (_, _) =>
            {
                dialled++;
                throw new InvalidOperationException("Dialled a refused address.");
            }));

        var failure = await Assert.ThrowsAsync<HttpRequestException>(() => http.GetAsync("https://rebinding.example/", Cancellation));

        var refused = EgressRefusedException.Find(failure);
        Assert.NotNull(refused);
        Assert.Equal(EgressRefusal.PrivateAddress, refused.Reason);
        Assert.Equal("rebinding.example", refused.Host);
        Assert.DoesNotContain("10.0.0.1", refused.Message, StringComparison.Ordinal);
        Assert.Equal(0, dialled);
    }

    [Fact]
    public void Handler_has_no_proxy_redirects_or_cookies_and_a_10_second_connect_timeout()
    {
        using var handler = EgressHttp.Create();

        Assert.False(handler.UseProxy);
        Assert.Null(handler.Proxy);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.Equal(TimeSpan.FromSeconds(10), handler.ConnectTimeout);
        Assert.NotNull(handler.ConnectCallback);
    }
}
