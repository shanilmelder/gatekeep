using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using Gatekeep.Kernel.Secrets;
using Xunit;

namespace Gatekeep.Tests.Isolation.Custody;

/// <summary>
/// Story 12.7: the real rotation scripts against OpenBao 2.7.2, every step as the runbook runs it.
/// <c>prepare</c>, rotation mode, the root-key step, base mode, <c>finish</c>, and the refusals in
/// between, with values made before the rotation checked after it through host AppRole tokens
/// issued before it. The stand-in start script mounts the files as Compose and
/// <c>deploy/compose.rotate.yaml</c> would.
/// </summary>
public sealed class MasterKeyRotationTests(RotationOpenBaoFixture bao) : IClassFixture<RotationOpenBaoFixture>
{
    private const string Prepare = "sh /opt/gatekeep/openbao/rotate-master-key.sh prepare";
    private const string Finish = "sh /opt/gatekeep/openbao/rotate-master-key.sh finish";
    private const string RootStep = "/opt/gatekeep/openbao/rotate-root-key.sh";
    private const string RootMarker = "/run/openbao/.master-key-root-rotated";

    /// <summary>
    /// Writes /tmp/leaky.sh: the root step, except that it revokes no token, its own or another, and leaves
    /// it in /tmp/leaked, so a test has a root token left behind and can look tokens up with one.
    /// </summary>
    private const string LeakyRootStep =
        """sed -e 's/bao token revoke -self/true/' -e 's/bao token revoke -accessor/true/' -e '/^export BAO_TOKEN="\$TOKEN"$/a printf "%s" "$BAO_TOKEN" > /tmp/leaked' """ + RootStep + " > /tmp/leaky.sh";

    private static readonly byte[] Data = "credential-equivalent value"u8.ToArray();
    private static readonly TimeSpan UnsealDeadline = TimeSpan.FromSeconds(60);

    private readonly List<string> _outputs = [];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Full_rotation_keeps_every_value_and_leaves_the_old_generation_unable_to_unseal()
    {
        var totp = KeyName.ForTenant(TenantKeyClass.Totp, bao.TenantA);
        var hmac = KeyName.ForTenant(TenantKeyClass.Hmac, bao.TenantA);
        var tpk = KeyName.ForTenant(TenantKeyClass.TokenProtection, bao.TenantA);

        // Values made before the rotation, by hosts whose tokens outlive it.
        using var hosted = bao.FollowingCustody(OpenBaoFixture.Hosted);
        using var worker = bao.FollowingCustody(OpenBaoFixture.Worker);
        var signature = await hosted.SignAsync(bao.SigningA, Data, Cancellation);
        var ciphertext = await hosted.EncryptAsync(totp, bao.TenantA, new Secret<byte[]>(Data), Cancellation);
        var mac = await hosted.HmacAsync(hmac, new Secret<byte[]>(Data), Cancellation);
        var wrapped = await worker.CreateWrappedDataKeyAsync(tpk, bao.TenantA, Cancellation);
        var dataKey = (await hosted.DecryptAsync(tpk, bao.TenantA, wrapped, Cancellation)).Use(b => b.ToArray());

        var generation1 = await bao.ReadKeyFileAsync();
        Assert.Equal("gatekeep-master-1", (await bao.ReadTextAsync(OpenBaoFixture.KeyIdFile)).Trim());
        await AssertRenderedAsync(rotationMode: false, current: 1);

        // The root step outside rotation mode is refused before any share is read.
        var early = await RunAsync($"sh {RootStep} < {OpenBaoFixture.EscrowFile}");
        Assert.NotEqual(0, early.ExitCode);
        Assert.Contains("isn't in rotation mode", early.Stderr);
        Assert.Contains("No share was read", early.Stderr);

        // finish with nothing to finish.
        var nothing = await RunAsync(Finish);
        Assert.NotEqual(0, nothing.ExitCode);
        Assert.Contains("nothing to finish", nothing.Stderr);

        // prepare: generation 1 aside, generation 2 written.
        var prepared = await RunAsync(Prepare);
        Assert.True(prepared.ExitCode == 0, prepared.Stderr);
        Assert.Contains("moved generation 1 to /secrets/previous/master-key", prepared.Stdout);
        Assert.Contains("wrote generation 2 to /secrets/master-key", prepared.Stdout);
        Assert.Matches(@"master-key-gen2-\d{4}-\d{2}-\d{2}\b", prepared.Stdout);
        var generation2 = await bao.ReadKeyFileAsync();
        Assert.Equal(32, generation2.Length);
        Assert.NotEqual(generation1, generation2);
        Assert.Equal(generation1, await OpenBaoFixture.ReadBytesAsync(bao.Container, OpenBaoFixture.PreviousDirectory + "/master-key"));
        Assert.Equal("gatekeep-master-2", (await bao.ReadTextAsync(OpenBaoFixture.KeyIdFile)).Trim());
        Assert.Equal("gatekeep-master-1", (await bao.ReadTextAsync(OpenBaoFixture.PreviousDirectory + "/master-key-id")).Trim());
        Assert.Equal(
            "400 100:1000\n400 100:1000\n444 100:1000\n400 100:1000",
            (await bao.ExecAsync("stat", "-c", "%a %u:%g",
                OpenBaoFixture.PreviousDirectory + "/master-key", OpenBaoFixture.PreviousDirectory + "/master-key-id",
                OpenBaoFixture.KeyIdFile, OpenBaoFixture.KeyFile)).Stdout.Trim());

        // A second prepare moves nothing.
        var again = await RunAsync(Prepare);
        Assert.NotEqual(0, again.ExitCode);
        Assert.Contains("/secrets/previous already holds a key", again.Stderr);
        Assert.Equal(generation2, await bao.ReadKeyFileAsync());
        Assert.Equal(generation1, await OpenBaoFixture.ReadBytesAsync(bao.Container, OpenBaoFixture.PreviousDirectory + "/master-key"));

        // Base mode on generation 2 alone, before the seal rotated: sealed. finish refuses first for
        // want of the root-key step's marker, the Operator having skipped steps 3 and 4, then, with a
        // marker standing in for it, because OpenBao is sealed. Generation 1 stays either way.
        await bao.RestartAsync(rotationMode: false);
        Assert.False(await bao.UnsealsWithinAsync(TimeSpan.FromSeconds(10)), "OpenBao unsealed on a generation that sealed nothing.");
        var skipped = await RunAsync(Finish);
        Assert.NotEqual(0, skipped.ExitCode);
        Assert.Contains("the root-key step hasn't run since prepare", skipped.Stderr);
        await bao.ExecAsync("touch", RootMarker);
        var sealedFinish = await RunAsync(Finish);
        Assert.NotEqual(0, sealedFinish.ExitCode);
        Assert.Contains("isn't unsealed", sealedFinish.Stderr);
        await bao.ExecAsync("rm", "-f", RootMarker);
        Assert.Equal(generation1, await OpenBaoFixture.ReadBytesAsync(bao.Container, OpenBaoFixture.PreviousDirectory + "/master-key"));

        // Rotation mode: both generations, so it unseals and re-wraps under generation 2.
        await bao.RestartAsync(rotationMode: true);
        Assert.True(await bao.UnsealsWithinAsync(UnsealDeadline), "OpenBao didn't unseal in rotation mode.");
        await AssertRenderedAsync(rotationMode: true, current: 2);

        // Wrong or too few shares: no token, nothing rotated, no attempt left open.
        var tooFew = await RunAsync($"sed -n '/recovery_keys_b64/,/]/p' {OpenBaoFixture.EscrowFile} | grep -o '\"[A-Za-z0-9+/=]*\"' | tr -d '\"' | head -n 2 | sh {RootStep}");
        Assert.NotEqual(0, tooFew.ExitCode);
        Assert.Contains("needs 3 recovery shares and standard input held 2", tooFew.Stderr);
        var wrong = await RunAsync($"for i in 1 2 3; do head -c 33 /dev/urandom | base64; done | sh {RootStep}");
        Assert.NotEqual(0, wrong.ExitCode);
        Assert.Contains("refused a recovery share", wrong.Stderr);
        Assert.False(await AttemptStartedAsync(), "A root generation attempt was left open.");
        Assert.False((await bao.ExecAsync("test", "-e", RootMarker)).ExitCode == 0, "A failed root step left its marker.");

        // A root token left behind, as by a run that couldn't revoke its own: a copy of the step
        // that keeps its token, which also rotates (setup's term 1 becomes 2).
        var leaky = await RunAsync($"{LeakyRootStep} && sh /tmp/leaky.sh < {OpenBaoFixture.EscrowFile}");
        Assert.True(leaky.ExitCode == 0, leaky.Stderr);
        Assert.Contains("the key term is now 2", leaky.Stdout);

        // The root step, with the escrowed file on standard input: it revokes the left-over token
        // and its own, and the term rises again.
        var rooted = await RunAsync($"sh {RootStep} < {OpenBaoFixture.EscrowFile}");
        Assert.True(rooted.ExitCode == 0, rooted.Stderr);
        Assert.Contains("the key term is now 3", rooted.Stdout);
        Assert.Contains("revoked 1 other root token", rooted.Stderr);
        Assert.False(await AttemptStartedAsync(), "A root generation attempt was left open.");
        Assert.Equal("3", (await bao.ReadTextAsync(RootMarker)).Trim());
        Assert.Contains("Code: 403", (await bao.ExecAsync("sh", "-c", $"BAO_ADDR={OpenBaoFixture.Socket} BAO_TOKEN=\"$(cat /tmp/leaked)\" bao token lookup 2>&1")).Stdout);

        // No root token survives: one more leaky run lists every token with its own, and finds
        // only itself with the root policy, then revokes itself.
        var census = await bao.ExecAsync("sh", "-c", $"""
            sh /tmp/leaky.sh < {OpenBaoFixture.EscrowFile} > /dev/null 2>&1 || exit 9
            export BAO_ADDR={OpenBaoFixture.Socket} BAO_TOKEN="$(cat /tmp/leaked)"
            n=0
            for a in $(bao list -format=json auth/token/accessors | grep -o '"[A-Za-z0-9.]*"' | tr -d '"'); do
                bao token lookup -format=json -accessor "$a" | tr -d ' \n' | grep -q '"policies":\["root"\]' && n=$((n + 1))
            done
            bao token revoke -self > /dev/null
            rm -f /tmp/leaked
            echo "$n"
            """);
        Assert.Equal("1", census.Stdout.Trim());

        // Still in rotation mode, so finish refuses even with the marker.
        var stillRotating = await RunAsync(Finish);
        Assert.NotEqual(0, stillRotating.ExitCode);
        Assert.Contains("still in rotation mode", stillRotating.Stderr);

        // Base mode on generation 2 alone, then finish shreds generation 1's online copy.
        await bao.RestartAsync(rotationMode: false);
        Assert.True(await bao.UnsealsWithinAsync(UnsealDeadline), "OpenBao didn't unseal on generation 2 alone.");
        await AssertRenderedAsync(rotationMode: false, current: 2);
        var finished = await RunAsync(Finish);
        Assert.True(finished.ExitCode == 0, finished.Stderr);
        Assert.Contains("keep that generation escrowed until the last backup taken before this rotation has expired", finished.Stdout);
        Assert.Equal(string.Empty, (await bao.ExecAsync("ls", "-A", OpenBaoFixture.PreviousDirectory)).Stdout.Trim());

        // Every earlier value still verifies, decrypts, matches or unwraps, on tokens from before.
        var versions = await hosted.GetPublicKeysAsync(bao.SigningA, Cancellation);
        Assert.True(VerifiesLocally(versions.Single(v => v.KeyVersion == signature.KeyVersion).PublicKeyPem, signature));
        Assert.True(VerifiesLocally(versions[^1].PublicKeyPem, await hosted.SignAsync(bao.SigningA, Data, Cancellation)));
        Assert.Equal(Data, (await hosted.DecryptAsync(totp, bao.TenantA, ciphertext, Cancellation)).Use(b => b.ToArray()));
        var macAfter = await hosted.HmacAsync(hmac, new Secret<byte[]>(Data), Cancellation);
        Assert.Equal(mac.KeyVersion, macAfter.KeyVersion);
        Assert.Equal(mac.Value, macAfter.Value);
        Assert.Equal(dataKey, (await hosted.DecryptAsync(tpk, bao.TenantA, wrapped, Cancellation)).Use(b => b.ToArray()));

        // No step printed a key byte of either generation, a recovery share or a token.
        var escrow = await bao.ReadTextAsync(OpenBaoFixture.EscrowFile);
        AssertNothingLeaked(generation1, generation2, escrow);

        // Generation 1 alone, with its own ID, no longer opens the data.
        await bao.ExecAsync("sh", "-c",
            $"rm -f {OpenBaoFixture.KeyFile} {OpenBaoFixture.KeyIdFile} && echo {Convert.ToBase64String(generation1)} | base64 -d > {OpenBaoFixture.KeyFile} && echo gatekeep-master-1 > {OpenBaoFixture.KeyIdFile}");
        await bao.RestartAsync(rotationMode: false);
        Assert.False(await bao.UnsealsWithinAsync(TimeSpan.FromSeconds(15)), "Generation 1 still unseals after the rotation.");
        var (stdout, stderr) = await bao.Container.GetLogsAsync(DateTime.UtcNow.AddSeconds(-30), ct: Cancellation);
        Assert.Contains("unknown key id", stdout + stderr);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("directory")]
    [InlineData("")]
    [InlineData("gk-1")]
    [InlineData("gatekeep-master-0")]
    [InlineData("gatekeep-master-01")]
    [InlineData("gatekeep-master-1 ")]
    [InlineData("the key")]
    public async Task OpenBao_refuses_to_start_on_a_missing_or_bad_key_id_naming_the_file(string id)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var (exitCode, logs) = await StartWithKeyIdAsync(key, id);

        Assert.NotEqual(0, exitCode);
        Assert.Contains("refusing to start: /run/secrets/master_key_id", logs);
        Assert.DoesNotContain("OpenBao server started", logs);
        AssertHoldsNoKey(logs, key);
    }

    /// <summary>
    /// Rotation mode refuses a previous pair that's only half there (Compose leaves an empty
    /// directory for the missing file) and a current generation that isn't one above the previous.
    /// </summary>
    [Theory]
    [InlineData("mkdir /secrets/previous/master-key && echo gatekeep-master-1 > /secrets/previous/master-key-id",
        "refusing to start: rotation mode needs /run/secrets/master_key_previous as a file")]
    [InlineData("head -c 32 /dev/urandom > /secrets/previous/master-key && echo gatekeep-master-5 > /secrets/previous/master-key-id",
        "refusing to start: in rotation mode the current generation (2) must be one above the previous (5)")]
    public async Task Rotation_mode_refuses_a_half_present_or_out_of_sequence_previous_generation(string previous, string refusal)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var (exitCode, logs) = await StartWithKeyIdAsync(key, "gatekeep-master-2", previous: previous);

        Assert.NotEqual(0, exitCode);
        Assert.Contains(refusal, logs);
        Assert.DoesNotContain("OpenBao server started", logs);
        AssertHoldsNoKey(logs, key);
    }

    [Fact]
    public async Task A_valid_key_id_of_any_generation_is_rendered_into_the_seal()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var (exitCode, logs) = await StartWithKeyIdAsync(key, "gatekeep-master-7", expectRunning: true);

        Assert.Equal(-1, exitCode);
        Assert.Contains("start-openbao: generation 7.", logs);
        AssertHoldsNoKey(logs, key);
    }

    /// <summary>
    /// A fresh OpenBao whose key directory holds <paramref name="key"/> and, unless
    /// <paramref name="id"/> is <c>missing</c>, a key ID file holding it (<c>directory</c>: the
    /// empty directory Compose leaves; <c>the key</c>: the key's hex, written there by mistake).
    /// With <paramref name="previous"/>, a script that writes previous/, it starts in rotation mode.
    /// Returns its exit code (-1 while it runs) and its logs.
    /// </summary>
    private static async Task<(long ExitCode, string Logs)> StartWithKeyIdAsync(
        byte[] key, string id, bool expectRunning = false, string? previous = null)
    {
        await using var keyVolume = new VolumeBuilder().WithName("gatekeep-keys-" + Guid.NewGuid().ToString("N")).Build();
        await keyVolume.CreateAsync(Cancellation);

        var write = id switch
        {
            "missing" => "true",
            "directory" => "mkdir /secrets/master-key-id",
            "the key" => "od -An -tx1 /secrets/master-key | tr -d ' \\n' > /secrets/master-key-id",
            _ => "printf '%s' \"$KEY_ID\" > /secrets/master-key-id",
        };
        await using (var writer = new ContainerBuilder(OpenBaoFixture.Image)
            .WithVolumeMount(keyVolume, OpenBaoFixture.KeyDirectory)
            .WithCreateParameterModifier(parameters => parameters.User = "root")
            .WithEnvironment("KEY_B64", Convert.ToBase64String(key))
            .WithEnvironment("KEY_ID", id)
            .WithEntrypoint("sh")
            .WithCommand("-c", $"echo \"$KEY_B64\" | base64 -d > /secrets/master-key && {write}"
                + (previous is null ? string.Empty : $" && mkdir -p /secrets/previous && {previous}"))
            .Build())
        {
            await writer.StartAsync(Cancellation);
            Assert.Equal(0, await writer.GetExitCodeAsync(Cancellation));
        }

        await using var container = OpenBaoFixture.Build(generateKey: false, keyVolume)
            .WithEnvironment("GATEKEEP_TEST_ROTATION_MODE", previous is null ? "0" : "1")
            .Build();
        await container.StartAsync(Cancellation);

        long exitCode;
        if (expectRunning)
        {
            var until = DateTime.UtcNow + UnsealDeadline;
            while (!(await container.GetLogsAsync(ct: Cancellation)).Stdout.Contains("OpenBao server started", StringComparison.Ordinal)
                && DateTime.UtcNow < until)
            {
                await Task.Delay(500, Cancellation);
            }

            var rendered = await container.ExecAsync(["cat", OpenBaoFixture.RenderedConfig], Cancellation);
            Assert.Contains("current_key_id = \"gatekeep-master-7\"", rendered.Stdout);
            exitCode = container.State == TestcontainersStates.Running ? -1 : 0;
        }
        else
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
            deadline.CancelAfter(UnsealDeadline);
            exitCode = await container.GetExitCodeAsync(deadline.Token);
        }

        var (stdout, stderr) = await container.GetLogsAsync(ct: Cancellation);
        return (exitCode, stdout + stderr);
    }

    /// <summary>One shell command in the OpenBao container, as root, kept for the leak check.</summary>
    private async Task<ExecResult> RunAsync(string command)
    {
        var result = await bao.ExecAsync("sh", "-c", command);
        _outputs.Add(result.Stdout + result.Stderr);
        return result;
    }

    /// <summary>The config start-openbao.sh rendered: unauthenticated generate-root on the socket in rotation mode only.</summary>
    private async Task AssertRenderedAsync(bool rotationMode, int current)
    {
        var config = await bao.ReadTextAsync(OpenBaoFixture.RenderedConfig);
        var unix = Regex.Match(config, @"(?s)listener ""unix"" \{(?<body>[^}]*)\}").Groups["body"].Value;
        var tcp = Regex.Match(config, @"(?s)listener ""tcp"" \{(?<body>[^}]*)\}").Groups["body"].Value;

        Assert.Contains($"current_key_id = \"gatekeep-master-{current}\"", config);
        Assert.Contains("disable_unauthed_generate_root_endpoints = true", tcp);
        if (rotationMode)
        {
            Assert.Contains("disable_unauthed_generate_root_endpoints = false", unix);
            Assert.Contains($"previous_key_id = \"gatekeep-master-{current - 1}\"", config);
            Assert.Contains("previous_key    = \"file:///run/secrets/master_key_previous\"", config);
        }
        else
        {
            Assert.Contains("disable_unauthed_generate_root_endpoints = true", unix);
            Assert.DoesNotContain("disable_unauthed_generate_root_endpoints = false", config);
            Assert.DoesNotMatch(@"(?m)^\s*previous_key", config);
        }

        Assert.DoesNotContain("@MASTER_KEY_ID@", config);
    }

    /// <summary>Whether a root generation attempt is open, asked without a token: rotation mode only.</summary>
    private async Task<bool> AttemptStartedAsync()
    {
        var attempt = await bao.ExecAsync("bao", "read", "-format=json", $"-address={OpenBaoFixture.Socket}", "sys/generate-root/attempt");
        Assert.Equal(0, attempt.ExitCode);
        using var json = JsonDocument.Parse(attempt.Stdout);
        return json.RootElement.GetProperty("data").GetProperty("started").GetBoolean();
    }

    private void AssertNothingLeaked(byte[] generation1, byte[] generation2, string escrow)
    {
        using var json = JsonDocument.Parse(escrow);
        var shares = json.RootElement.GetProperty("recovery_keys_b64").EnumerateArray()
            .Concat(json.RootElement.GetProperty("recovery_keys_hex").EnumerateArray())
            .Select(s => s.GetString()!)
            .Append(json.RootElement.GetProperty("root_token").GetString()!)
            .ToList();

        Assert.NotEmpty(_outputs);
        foreach (var output in _outputs)
        {
            AssertHoldsNoKey(output, generation1);
            AssertHoldsNoKey(output, generation2);
            Assert.All(shares, s => Assert.DoesNotContain(s, output, StringComparison.OrdinalIgnoreCase));
            // A root token or an OTP (26 base62 characters): a long run of token characters.
            Assert.DoesNotMatch(@"\b(?:s|hvs|b)\.[A-Za-z0-9]{16,}|[A-Za-z0-9]{22,}", output);
        }
    }

    private static void AssertHoldsNoKey(string text, byte[] key)
    {
        Assert.DoesNotContain(Encoding.Latin1.GetString(key), text, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToHexString(key), text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(key).TrimEnd('='), text, StringComparison.Ordinal);
    }

    private static bool VerifiesLocally(string publicKeyPem, KeySignature signature)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        return rsa.VerifyData(Data, signature.Value, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
