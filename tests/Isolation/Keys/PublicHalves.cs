using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Gatekeep.Tests.Isolation.Admins;

namespace Gatekeep.Tests.Isolation.Keys;

/// <summary>
/// The OpenBao stand-in's Transit keys for Host.Admin (Stories 9.1 and 9.2): an RSA-3072 public half
/// per <c>sig-</c> key, made on first read or create, at version 1 unless <see cref="Version"/> says
/// otherwise. A create (a request with a body) is recorded in <see cref="Created"/>, or answered 503
/// while <see cref="RefuseCreate"/> is set. A <c>mgmt-</c> key is refused, as the <c>host-admin</c>
/// policy refuses reading it.
/// </summary>
internal sealed class PublicHalves
{
    // Made once, before any request: generated per read, RSA-3072 on a loaded runner can outlast
    // the one custody bound a whole sample has (KeyCustodyCallTimeout), and the read is then 503.
    private static readonly RSAParameters[] Pool = [.. Enumerable.Range(0, 8).Select(_ =>
    {
        using var rsa = RSA.Create(3072);
        return rsa.ExportParameters(includePrivateParameters: false);
    })];

    private readonly ConcurrentDictionary<string, RSAParameters> _keys = new();

    private readonly ConcurrentQueue<string> _created = new();

    private int _next = -1;

    public PublicHalves(AdminHost host)
    {
        // Touched here, so the pool is built now and never inside a request's custody bound.
        _ = Pool.Length;
        host.OpenBao.RespondToBody = (path, body) =>
        {
            const string Keys = "/transit/keys/";
            var at = path.IndexOf(Keys, StringComparison.Ordinal);
            if (at < 0)
            {
                return AdminHost.Custody(path, body);
            }

            var name = path[(at + Keys.Length)..].Split('?')[0];
            if (!name.StartsWith("sig-", StringComparison.Ordinal))
            {
                return (403, """{"errors":["permission denied"]}""");
            }

            // A create sends the key type in its body; a public-half read sends none.
            if (!string.IsNullOrWhiteSpace(body))
            {
                if (RefuseCreate)
                {
                    return (503, """{"errors":["sealed"]}""");
                }

                _created.Enqueue(name);
            }

            var pem = Blank.ContainsKey(name) ? " " : Pem(name);
            var version = Version.GetValueOrDefault(name, 1);
            return (200, JsonSerializer.Serialize(new { data = new { type = "rsa-3072", keys = new Dictionary<string, object> { [$"{version}"] = new { public_key = pem } } } }));
        };
    }

    public ConcurrentDictionary<string, int> Version { get; } = new();

    /// <summary>Keys whose public half the stand-in gives as whitespace only: no PEM at all.</summary>
    public ConcurrentDictionary<string, bool> Blank { get; } = new();

    /// <summary>While set, every create is refused as a sealed OpenBao refuses it.</summary>
    public bool RefuseCreate { get; set; }

    /// <summary>The names of the keys created, in order.</summary>
    public IReadOnlyList<string> Created => [.. _created];

    /// <summary>The public parameters behind a <c>kid</c>, as the stand-in gave them.</summary>
    public RSAParameters Parameters(string kid) => _keys[kid[..kid.LastIndexOf(".v", StringComparison.Ordinal)]];

    private string Pem(string name)
    {
        // A distinct pooled key per name, so each kid still has its own public half.
        var parameters = _keys.GetOrAdd(name, _ => Pool[Interlocked.Increment(ref _next) % Pool.Length]);

        using var key = RSA.Create(parameters);
        return key.ExportSubjectPublicKeyInfoPem();
    }
}
