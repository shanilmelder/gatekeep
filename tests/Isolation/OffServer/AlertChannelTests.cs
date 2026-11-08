using System.Text.Json.Nodes;
using Gatekeep.Adapters.AlertChannel;
using Gatekeep.Adapters.Egress;
using Gatekeep.Kernel.Alerts;
using Xunit;

namespace Gatekeep.Tests.Isolation.OffServer;

/// <summary>
/// Story 1.30: the webhook adapter against a sink, through EgressHttp. One <c>POST</c> of exactly
/// the alert's fields with the bearer token; only 2xx delivers; nothing is retried; and no failure
/// carries the address, the token or the sink's answer.
/// </summary>
public sealed class AlertChannelTests : IAsyncLifetime
{
    private static readonly AlertDeployment Deployment = new("admin.gatekeep-admin.test");

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-alerts-").FullName;
    private readonly string _token = "alert-token-" + Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(12));

    private AlertSinkFixture _sink = null!;

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private string TokenFile => Path.Combine(_directory, "token");

    public async ValueTask InitializeAsync()
    {
        _sink = await AlertSinkFixture.StartAsync();
        await File.WriteAllTextAsync(TokenFile, _token + "\n", Cancellation);
    }

    public async ValueTask DisposeAsync()
    {
        await _sink.DisposeAsync();
        Directory.Delete(_directory, recursive: true);
    }

    [Fact]
    public async Task Alert_reaches_the_sink_once_with_only_its_fields_and_the_bearer_token()
    {
        var tenantId = Guid.CreateVersion7();
        var alert = SecurityAlert.Raise(SecurityAlertCode.Test, Deployment, TimeProvider.System, tenantId);
        using var channel = Channel();

        await channel.SendAsync(alert, Cancellation);

        var request = Assert.Single(_sink.Requests);
        Assert.Equal("POST", request.Method);
        Assert.Equal("/hooks/gatekeep?channel=security", request.PathAndQuery);
        Assert.Equal($"Bearer {_token}", request.Headers["Authorization"]);
        Assert.Equal("application/json", request.Headers["Content-Type"]);
        Assert.False(request.Headers.ContainsKey("Cookie"));

        var body = JsonNode.Parse(request.Body)!.AsObject();
        Assert.Equal(["alertId", "code", "deployment", "raisedAt", "summary", "tenantId"], body.Select(m => m.Key).Order(StringComparer.Ordinal));
        Assert.Equal(alert.AlertId.ToString("D"), (string?)body["alertId"]);
        Assert.Equal("operations.alert.test", (string?)body["code"]);
        Assert.Equal(Deployment.Name, (string?)body["deployment"]);
        Assert.Equal(SecurityAlertCode.Test.Summary, (string?)body["summary"]);
        Assert.Equal(tenantId.ToString("D"), (string?)body["tenantId"]);
        Assert.EndsWith("Z", (string?)body["raisedAt"], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(404)]
    [InlineData(500)]
    [InlineData(302)]
    public async Task Answer_other_than_2xx_is_Rejected_once_with_nothing_of_it_in_the_failure(int status)
    {
        _sink.Status = status;
        // A redirect to a public URL is never followed.
        _sink.Location = status == 302 ? "https://example.com/elsewhere" : null;
        using var channel = Channel();

        var failure = await Assert.ThrowsAsync<AlertChannelException>(() =>
            channel.SendAsync(SecurityAlert.Raise(SecurityAlertCode.Test, Deployment, TimeProvider.System), Cancellation));

        Assert.Equal(AlertChannelFailure.Rejected, failure.Failure);
        Assert.Equal(AlertOperation.Send, failure.Operation);
        Assert.Single(_sink.Requests);
        AssertLeaksNothing(failure);
    }

    [Fact]
    public async Task Sink_that_answers_too_late_is_Unavailable()
    {
        _sink.Delay = TimeSpan.FromSeconds(5);
        using var channel = Channel(timeout: TimeSpan.FromSeconds(1));

        var failure = await Assert.ThrowsAsync<AlertChannelException>(() =>
            channel.SendAsync(SecurityAlert.Raise(SecurityAlertCode.Test, Deployment, TimeProvider.System), Cancellation));

        Assert.Equal(AlertChannelFailure.Unavailable, failure.Failure);
        // Not retried: the sink saw the one request that timed out.
        Assert.Single(_sink.Requests);
        AssertLeaksNothing(failure);
    }

    [Fact]
    public async Task Sink_nobody_listens_on_is_Unavailable()
    {
        var closed = new Uri($"http://127.0.0.1:{Hosting.HostProcess.FreePort()}/hooks/gatekeep");
        using var channel = new WebhookAlertChannel(ObjectLockFixture.Permitted(), new WebhookAlertOptions { Url = closed, TokenFile = TokenFile });

        var failure = await Assert.ThrowsAsync<AlertChannelException>(() =>
            channel.SendAsync(SecurityAlert.Raise(SecurityAlertCode.Test, Deployment, TimeProvider.System), Cancellation));

        Assert.Equal(AlertChannelFailure.Unavailable, failure.Failure);
        AssertLeaksNothing(failure);
    }

    [Theory]
    [InlineData("https://10.0.0.1/hook")]
    [InlineData("https://127.0.0.1/hook")]
    [InlineData("https://[::ffff:192.168.1.1]/hook")]
    [InlineData("https://[fd00::1]/hook")]
    [InlineData("https://host.docker.internal/hook")]
    [InlineData("https://localhost/hook")]
    public async Task Private_target_is_Refused_through_the_real_EgressHttp_and_nothing_is_sent(string url)
    {
        using var channel = new WebhookAlertChannel(EgressHttp.Create(), new WebhookAlertOptions { Url = new Uri(url), TokenFile = TokenFile });

        var failure = await Assert.ThrowsAsync<AlertChannelException>(() =>
            channel.SendAsync(SecurityAlert.Raise(SecurityAlertCode.Test, Deployment, TimeProvider.System), Cancellation));

        Assert.Equal(AlertChannelFailure.Refused, failure.Failure);
        Assert.Equal(AlertRefusal.Address, failure.Refusal);
        Assert.Empty(_sink.Requests);
        AssertLeaksNothing(failure);
    }

    [Fact]
    public async Task Sink_on_loopback_is_Refused_without_the_test_permit()
    {
        // The sink is up: only the egress rule stops the request.
        var https = new UriBuilder(_sink.Url) { Scheme = Uri.UriSchemeHttps }.Uri;
        using var channel = new WebhookAlertChannel(EgressHttp.Create(), new WebhookAlertOptions { Url = https, TokenFile = TokenFile });

        var failure = await Assert.ThrowsAsync<AlertChannelException>(() =>
            channel.SendAsync(SecurityAlert.Raise(SecurityAlertCode.Test, Deployment, TimeProvider.System), Cancellation));

        Assert.Equal(AlertChannelFailure.Refused, failure.Failure);
        Assert.Equal(AlertRefusal.Address, failure.Refusal);
        Assert.Empty(_sink.Requests);
    }

    [Theory]
    [InlineData("")]
    [InlineData("changeme")]
    [InlineData("alert token")]
    [InlineData("alert\u0000token")]
    [InlineData("alert\u00e9token")]
    public async Task Empty_default_or_non_ASCII_token_is_Refused_and_nothing_is_sent(string token)
    {
        await File.WriteAllTextAsync(TokenFile, token, Cancellation);
        using var channel = Channel();

        var failure = await Assert.ThrowsAsync<AlertChannelException>(() =>
            channel.SendAsync(SecurityAlert.Raise(SecurityAlertCode.Test, Deployment, TimeProvider.System), Cancellation));

        Assert.Equal(AlertChannelFailure.Refused, failure.Failure);
        Assert.Equal(AlertRefusal.TokenFile, failure.Refusal);
        Assert.Empty(_sink.Requests);
    }

    [Theory]
    [InlineData("https://alerts.example.com/hook", true)]
    [InlineData("https://alerts.example.com/hook?name=gatekeep", true)]
    [InlineData("http://alerts.example.com/hook", false)]
    [InlineData("https://user:pass@alerts.example.com/hook", false)]
    [InlineData("https://alerts.example.com/hook#x", false)]
    [InlineData("alerts.example.com/hook", false)]
    [InlineData("/hook", false)]
    [InlineData("", false)]
    public void Webhook_URL_must_be_absolute_https_with_no_user_info(string url, bool accepted)
    {
        Assert.Equal(accepted, WebhookAlertOptions.TryParseUrl(url) is not null);
    }

    private WebhookAlertChannel Channel(TimeSpan? timeout = null) =>
        new(ObjectLockFixture.Permitted(), new WebhookAlertOptions
        {
            Url = _sink.Url,
            TokenFile = TokenFile,
            Timeout = timeout ?? TimeSpan.FromSeconds(10),
        });

    private void AssertLeaksNothing(Exception failure)
    {
        var text = failure.ToString();
        Assert.Null(failure.InnerException);
        Assert.DoesNotContain(_token, text, StringComparison.Ordinal);
        Assert.DoesNotContain("127.0.0.1", text, StringComparison.Ordinal);
        Assert.DoesNotContain("hooks/gatekeep", text, StringComparison.Ordinal);
        Assert.DoesNotContain("sink error", text, StringComparison.Ordinal);
    }
}
