using System.Text.RegularExpressions;
using System.Xml.Linq;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// AD-26, Story 1.30: every outbound HTTP request in <c>src/</c> goes through <c>EgressHttp</c>.
/// Only <c>Adapters.Egress</c> makes a handler, beside the two allowed exceptions: OpenBao's unix
/// socket handler (<c>OpenBaoKeyCustody.CreateHandler</c>) and the loopback health probe. No source
/// subclasses a handler, opens a socket, TCP client or web socket of its own, asks for HTTP/3 (whose
/// QUIC connection never passes through the vetted connect step), makes an <c>HttpClient</c> with no
/// handler, which would bring its own, or uses the client factory, and <c>Host.Admin</c> has no
/// egress at all.
/// </summary>
public class EgressRuleTests
{
    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj"];

    /// <summary>The only places a handler may be made.</summary>
    private static readonly string[] HandlerAllowed =
    [
        "src/Adapters/Egress/EgressHttp.cs",
        "src/Adapters/OpenBao/OpenBaoKeyCustody.cs",
        "src/Adapters/Hosting/HealthProbe.cs",
    ];

    /// <summary>The only places a socket may be opened: EgressHttp's vetted connect and OpenBao's unix socket.</summary>
    private static readonly string[] SocketAllowed = [HandlerAllowed[0], HandlerAllowed[1]];

    private const string AdminProject = "src/Gatekeep.Host.Admin/Gatekeep.Host.Admin.csproj";

    /// <summary>
    /// String and character literals and comments, matched in one pass from the left, so a <c>//</c>
    /// inside a URL can't hide the code after it, and a quote inside a comment can't hide a line.
    /// </summary>
    private static readonly Regex LiteralOrComment = new(
        @"(?<string>\$*""""""[\s\S]*?"""""""
        + @"|(?:\$@|@\$|@)""(?:[^""]|"""")*"""
        + @"|\$*""(?:[^""\\\r\n]|\\.)*"""
        + @"|'(?:[^'\\\r\n]|\\.)+')"
        + @"|(?<comment>//[^\r\n]*|/\*[\s\S]*?\*/)",
        RegexOptions.Compiled);

    private const string Handler = @"(?:global::)?(?:System\.Net\.Http\.)?(?:SocketsHttpHandler|HttpClientHandler|WinHttpHandler)";

    /// <summary>
    /// A handler: named after <c>new</c>; made by a target-typed <c>new()</c> for a local, field,
    /// property or expression-bodied member of a handler type; or a class deriving from one, or from
    /// <c>HttpMessageHandler</c> itself. A <c>DelegatingHandler</c> only wraps a handler it's given.
    /// </summary>
    private static readonly Regex MakesHandler = new(
        $@"\bnew\s+{Handler}\b"
        + $@"|\b{Handler}\??\s+\w+\s*(?:=|=>|\{{[^{{}}]*\}}\s*=|\([^()]*\)\s*=>)\s*new\s*\("
        + $@"|\b(?:class|record)\s+\w+[^{{;:]*:\s*(?:[\w.<>]+\s*,\s*)*(?:{Handler}|(?:global::)?(?:System\.Net\.Http\.)?HttpMessageHandler)\b",
        RegexOptions.Compiled);

    /// <summary>A connection that skips HTTP altogether: a raw socket, a TCP or UDP client, or a web socket.</summary>
    private static readonly Regex OpensSocket = new(
        @"\bnew\s+(?:global::)?(?:System\.Net\.Sockets\.)?(?:Socket|TcpClient|UdpClient)\s*\("
        + @"|\b(?:ClientWebSocket|TcpClient|UdpClient)\b"
        + @"|\.ConnectAsync\s*\(",
        RegexOptions.Compiled);

    /// <summary>HTTP/3, asked for directly or allowed by a version policy that can upgrade to it.</summary>
    private static readonly Regex AsksForHttp3 = new(@"\bVersion30\b|\bRequestVersionOrHigher\b", RegexOptions.Compiled);

    /// <summary>An <c>HttpClient</c> with no handler, a client factory, or the older request types, each bringing a handler of its own.</summary>
    private static readonly Regex BringsOwnHandler = new(
        @"\bnew\s+(?:global::)?(?:System\.Net\.Http\.)?HttpClient\s*(?:\(\s*\)|\{)"
        + @"|\bHttpClient\s+\w+\s*=\s*new\s*\(\s*\)"
        + @"|\bAddHttpClient\b|\bIHttpClientFactory\b"
        + @"|\b(?:WebClient|HttpWebRequest|WebRequest)\b",
        RegexOptions.Compiled);

    [Fact]
    public void Only_Egress_the_OpenBao_socket_and_the_health_probe_make_an_HTTP_handler()
    {
        var sources = Sources();

        Assert.Contains(sources, s => s.Path == HandlerAllowed[0] && MakesHandler.IsMatch(s.Code));
        Assert.Empty(HandlerViolations(sources));
    }

    [Theory]
    [InlineData("src/Adapters/AlertChannel/WebhookAlertChannel.cs", "var handler = new SocketsHttpHandler { UseProxy = false };", 1)]
    [InlineData("src/Modules/Notifications/Core/Smtp.cs", "using var http = new HttpClient(new HttpClientHandler());", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "SocketsHttpHandler handler = new() { AllowAutoRedirect = true };", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "var handler = new System.Net.Http.SocketsHttpHandler();", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "var url = \"https://example.com\"; var handler = new SocketsHttpHandler();", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "private SocketsHttpHandler Handler { get; } = new() { UseProxy = true };", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "private static SocketsHttpHandler Handler => new() { UseProxy = true };", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "private static HttpClientHandler Make() => new();", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "private SocketsHttpHandler? _handler = new();", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "internal sealed class Direct : HttpClientHandler { }", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "public sealed class Raw(int port) : System.Net.Http.SocketsHttpHandler { }", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "internal sealed class Own : HttpMessageHandler, IDisposable { }", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "internal sealed class Logged : DelegatingHandler { }", 0)]
    [InlineData("src/Gatekeep.Cli/X.cs", "// new SocketsHttpHandler() is EgressHttp's alone.", 0)]
    [InlineData("src/Gatekeep.Cli/X.cs", "var note = \"never new SocketsHttpHandler() here\";", 0)]
    [InlineData("src/Adapters/Egress/EgressHttp.cs", "return new SocketsHttpHandler { UseProxy = false };", 0)]
    [InlineData("src/Adapters/OpenBao/OpenBaoKeyCustody.cs", "var handler = new SocketsHttpHandler { UseProxy = false };", 0)]
    [InlineData("src/Adapters/Hosting/HealthProbe.cs", "new HttpClient(new SocketsHttpHandler { UseProxy = false })", 0)]
    [InlineData("src/Gatekeep.Cli/X.cs", "using var channel = new WebhookAlertChannel(EgressHttp.Create(), options);", 0)]
    public void Handler_detection(string path, string source, int expected)
    {
        Assert.Equal(expected, HandlerViolations([(path, Clean(source))]).Count);
    }

    [Fact]
    public void Only_Egress_and_the_OpenBao_socket_open_a_socket_TCP_client_or_web_socket()
    {
        var sources = Sources();

        Assert.Contains(sources, s => s.Path == HandlerAllowed[0] && OpensSocket.IsMatch(s.Code));
        Assert.Empty(SocketViolations(sources));
    }

    [Theory]
    [InlineData("src/Gatekeep.Cli/X.cs", "using var tcp = new TcpClient();", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "await tcp.ConnectAsync(host, 443, ct);", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "await Socket.ConnectAsync(SocketType.Stream, ProtocolType.Tcp, endpoint);", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "using var ws = new ClientWebSocket();", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "// A TcpClient would skip EgressHttp.", 0)]
    [InlineData("src/Adapters/Egress/EgressHttp.cs", "await socket.ConnectAsync(target, cancellationToken);", 0)]
    [InlineData("src/Adapters/OpenBao/OpenBaoKeyCustody.cs", "await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), ct);", 0)]
    [InlineData("src/Adapters/Hosting/HealthProbe.cs", "using var tcp = new TcpClient();", 1)]
    [InlineData("src/Gatekeep.Cli/X.cs", "await connection.OpenAsync(ct);", 0)]
    public void Socket_detection(string path, string source, int expected)
    {
        Assert.Equal(expected, SocketViolations([(path, Clean(source))]).Count);
    }

    [Fact]
    public void No_source_asks_for_HTTP_3()
    {
        Assert.Empty(Http3Violations(Sources()));
    }

    [Theory]
    [InlineData("request.Version = HttpVersion.Version30;", 1)]
    [InlineData("http.DefaultRequestVersion = System.Net.HttpVersion.Version30;", 1)]
    [InlineData("request.VersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;", 1)]
    [InlineData("request.Version = HttpVersion.Version11;", 0)]
    [InlineData("// Never HttpVersion.Version30: QUIC skips the ConnectCallback.", 0)]
    public void Http3_detection(string source, int expected)
    {
        Assert.Equal(expected, Http3Violations([("src/Gatekeep.Cli/X.cs", Clean(source))]).Count);
    }

    [Fact]
    public void No_source_makes_an_HttpClient_with_its_own_handler_or_uses_the_client_factory()
    {
        Assert.Empty(OwnHandlerViolations(Sources()));
    }

    [Theory]
    [InlineData("using var http = new HttpClient();", 1)]
    [InlineData("var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };", 1)]
    [InlineData("HttpClient http = new();", 1)]
    [InlineData("services.AddHttpClient(\"alerts\");", 1)]
    [InlineData("public Sender(IHttpClientFactory factory) { }", 1)]
    [InlineData("var request = WebRequest.Create(url);", 1)]
    [InlineData("using var web = new WebClient();", 1)]
    [InlineData("var hook = \"https://hooks.example.com\"; using var http = new HttpClient();", 1)]
    [InlineData("_http = new HttpClient(handler, disposeHandler: true) { Timeout = options.Timeout };", 0)]
    [InlineData("using var http = new HttpClient(EgressHttp.Create());", 0)]
    [InlineData("// Never new HttpClient(): it brings its own handler.", 0)]
    public void Own_handler_detection(string source, int expected)
    {
        Assert.Equal(expected, OwnHandlerViolations([("src/Gatekeep.Cli/X.cs", Clean(source))]).Count);
    }

    [Theory]
    [InlineData("var a = \"x // y\"; new B();", "var a = \"\"; new B();")]
    [InlineData("var a = @\"c:\\\" + \"\"\" // \"\"\"; new B();", "var a = \"\" + \"\"; new B();")]
    [InlineData("var c = '\"'; new B(); // \"", "var c = \"\"; new B();  ")]
    [InlineData("/* \" */ new B();", "  new B();")]
    public void Literals_are_emptied_before_comments_are_removed(string source, string cleaned)
    {
        Assert.Equal(cleaned, Clean(source));
    }

    [Fact]
    public void Host_Admin_never_references_Adapters_Egress_or_names_EgressHttp()
    {
        var references = XDocument.Load(Path.Combine(Root, AdminProject))
            .Descendants("ProjectReference")
            .Select(r => r.Attribute("Include")!.Value.Replace('\\', '/'));
        Assert.DoesNotContain(references, r => r.Contains("Adapters/Egress/", StringComparison.Ordinal));
        Assert.DoesNotContain(EdgeList.Load(Root), e => e.From == "Host.Admin" && e.To == "Adapters.Egress");

        var admin = Sources().Where(s => s.Path.StartsWith("src/Gatekeep.Host.Admin/", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(admin);
        Assert.DoesNotContain(admin, s => s.Code.Contains("EgressHttp", StringComparison.Ordinal) || s.Code.Contains("Gatekeep.Adapters.Egress", StringComparison.Ordinal));
    }

    [Fact]
    public void Egress_permit_stays_internal_and_nothing_outside_Egress_names_it()
    {
        var egress = Sources().Single(s => s.Path == HandlerAllowed[0]);

        Assert.Matches(@"(?m)^internal sealed record EgressPermit\b", egress.Code);
        Assert.Matches(@"(?m)^\s*internal static SocketsHttpHandler Create\(\s*EgressPermit permit\b", egress.Code);
        Assert.DoesNotContain(
            Sources(),
            s => !s.Path.StartsWith("src/Adapters/Egress/", StringComparison.Ordinal) && s.Code.Contains("EgressPermit", StringComparison.Ordinal));
    }

    private static List<string> HandlerViolations(IEnumerable<(string Path, string Code)> sources) =>
        [.. sources
            .Where(s => !HandlerAllowed.Contains(s.Path) && MakesHandler.IsMatch(s.Code))
            .Select(s => $"{s.Path} makes an HTTP handler: outbound HTTP goes through EgressHttp (AD-26).")];

    private static List<string> SocketViolations(IEnumerable<(string Path, string Code)> sources) =>
        [.. sources
            .Where(s => !SocketAllowed.Contains(s.Path) && OpensSocket.IsMatch(s.Code))
            .Select(s => $"{s.Path} opens a connection of its own: outbound traffic goes through EgressHttp (AD-26).")];

    private static List<string> Http3Violations(IEnumerable<(string Path, string Code)> sources) =>
        [.. sources
            .Where(s => AsksForHttp3.IsMatch(s.Code))
            .Select(s => $"{s.Path} asks for HTTP/3, whose QUIC connection skips EgressHttp's vetted connect (AD-26).")];

    private static List<string> OwnHandlerViolations(IEnumerable<(string Path, string Code)> sources) =>
        [.. sources
            .Where(s => BringsOwnHandler.IsMatch(s.Code))
            .Select(s => $"{s.Path} makes an HTTP client with a handler of its own: pass EgressHttp.Create() (AD-26).")];

    /// <summary>The code with every literal emptied and every comment blanked.</summary>
    private static string Clean(string code) =>
        LiteralOrComment.Replace(code, m => m.Groups["string"].Success ? "\"\"" : " ");

    /// <summary>Every C# source in <c>src/</c>, by its repository path, cleaned of literals and comments.</summary>
    private static List<(string Path, string Code)> Sources() =>
        [.. Files(Path.Combine(Root, "src"))
            .Select(f => (Path.GetRelativePath(Root, f).Replace('\\', '/'), Clean(File.ReadAllText(f))))];

    private static IEnumerable<string> Files(string directory) =>
        Directory.EnumerateFiles(directory, "*.cs")
            .Concat(Directory.EnumerateDirectories(directory)
                .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
                .SelectMany(Files));
}
