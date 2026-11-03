using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Gatekeep.Adapters.Fido2;
using Gatekeep.Kernel.WebAuthn;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.22, threat-model gap G-8: the Fido2 adapter takes the RP ID and origin on every call
/// and keeps none. One verifier serves two Relying Parties in turn, each response verifying only
/// against its own; the origin must match exactly, and <c>crossOrigin</c> or a <c>topOrigin</c>
/// is refused, as are a missing UV flag, an excluded credential and another challenge.
/// </summary>
public sealed class Fido2AdapterTests
{
    private static readonly WebAuthnRelyingParty Admin = new("admin.gatekeep.test", "Gatekeep", "https://admin.gatekeep.test");

    private static readonly WebAuthnRelyingParty Other = new("other.example", "Other", "https://other.example:8443");

    private static readonly WebAuthnUser User = new(RandomNumberGenerator.GetBytes(64), "Deployment Owner", "Deployment Owner");

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task One_verifier_serves_each_Relying_Party_it_is_given_per_call()
    {
        var verifier = Fido2WebAuthn.Create();
        using var authenticator = new SoftwareAuthenticator();

        foreach (var party in new[] { Admin, Other, Admin })
        {
            var challenge = RandomNumberGenerator.GetBytes(32);
            var options = verifier.BeginRegistration(new WebAuthnRegistrationBegin(party, User, [], challenge));
            Assert.Equal(party.Id, options.RelyingParty.Id);
            Assert.Equal(party.Name, options.RelyingParty.Name);
            Assert.Equal(challenge, options.Challenge);
            Assert.Equal([-7, -257], options.PublicKeyParameters.Select(p => p.Algorithm));
            Assert.Equal(("none", "preferred", "required"), (options.Attestation, options.ResidentKey, options.UserVerification));

            var result = await FinishAsync(verifier, party, challenge, authenticator, party.Id, party.Origin);
            Assert.True(result.Verified, $"{party.Id}: {result.Refusal}");
            Assert.Equal(authenticator.CredentialId, result.Credential!.CredentialId);
            Assert.Equal(authenticator.Aaguid, result.Credential.Aaguid);
            Assert.True(result.Credential.UserVerified);
        }
    }

    [Fact]
    public async Task Response_for_one_Relying_Party_is_refused_by_another()
    {
        var verifier = Fido2WebAuthn.Create();
        using var authenticator = new SoftwareAuthenticator();
        var challenge = RandomNumberGenerator.GetBytes(32);

        // Made for Admin, verified as Other: its origin is wrong first.
        var crossed = await FinishAsync(verifier, Other, challenge, authenticator, Admin.Id, Admin.Origin);
        Assert.Equal(WebAuthnRefusal.OriginMismatch, crossed.Refusal);

        // Other's origin, but Admin's RP ID in the authenticator data.
        var wrongRp = await FinishAsync(verifier, Other, challenge, authenticator, Admin.Id, Other.Origin);
        Assert.Equal(WebAuthnRefusal.RpIdMismatch, wrongRp.Refusal);
    }

    [Theory]
    [InlineData("https://ADMIN.gatekeep.test")]
    [InlineData("https://admin.gatekeep.test:443")]
    [InlineData("https://admin.gatekeep.test/")]
    [InlineData("http://admin.gatekeep.test")]
    [InlineData("https://evil.gatekeep.test")]
    public async Task Origin_must_be_exactly_the_Relying_Partys(string origin)
    {
        using var authenticator = new SoftwareAuthenticator();

        var result = await FinishAsync(Fido2WebAuthn.Create(), Admin, RandomNumberGenerator.GetBytes(32), authenticator, Admin.Id, origin);

        Assert.Equal(WebAuthnRefusal.OriginMismatch, result.Refusal);
    }

    [Fact]
    public async Task Cross_origin_or_a_top_origin_is_refused()
    {
        using var authenticator = new SoftwareAuthenticator();
        var challenge = RandomNumberGenerator.GetBytes(32);

        var cross = await FinishAsync(Fido2WebAuthn.Create(), Admin, challenge, authenticator, Admin.Id, Admin.Origin, new AttestationTweaks { CrossOrigin = true });
        var top = await FinishAsync(Fido2WebAuthn.Create(), Admin, challenge, authenticator, Admin.Id, Admin.Origin, new AttestationTweaks { TopOrigin = Admin.Origin });
        var sameOrigin = await FinishAsync(Fido2WebAuthn.Create(), Admin, challenge, authenticator, Admin.Id, Admin.Origin, new AttestationTweaks { CrossOrigin = false });

        Assert.Equal(WebAuthnRefusal.CrossOrigin, cross.Refusal);
        Assert.Equal(WebAuthnRefusal.CrossOrigin, top.Refusal);
        Assert.True(sameOrigin.Verified);
    }

    [Fact]
    public async Task Missing_user_verification_an_excluded_credential_and_another_challenge_are_refused()
    {
        var verifier = Fido2WebAuthn.Create();
        using var authenticator = new SoftwareAuthenticator();
        var challenge = RandomNumberGenerator.GetBytes(32);

        var unverified = await FinishAsync(verifier, Admin, challenge, authenticator, Admin.Id, Admin.Origin, new AttestationTweaks { UserVerified = false });
        Assert.Equal(WebAuthnRefusal.UserNotVerified, unverified.Refusal);

        var excluded = await FinishAsync(
            verifier, Admin, challenge, authenticator, Admin.Id, Admin.Origin, exclude: [new("public-key", authenticator.CredentialId, ["usb"])]);
        Assert.Equal(WebAuthnRefusal.ExcludedCredential, excluded.Refusal);

        var other = await FinishAsync(
            verifier,
            Admin,
            challenge,
            authenticator,
            Admin.Id,
            Admin.Origin,
            new AttestationTweaks { Challenge = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32)) });
        Assert.Equal(WebAuthnRefusal.ChallengeMismatch, other.Refusal);
    }

    [Fact]
    public void Begin_sends_each_excluded_credential_with_its_transports()
    {
        var id = RandomNumberGenerator.GetBytes(16);

        var options = Fido2WebAuthn.Create().BeginRegistration(
            new WebAuthnRegistrationBegin(Admin, User, [new("public-key", id, ["usb", "nfc", "carrier-pigeon"])], RandomNumberGenerator.GetBytes(32)));

        var excluded = Assert.Single(options.ExcludeCredentials);
        Assert.Equal(("public-key", id), (excluded.Type, excluded.Id));
        Assert.Equal(["usb", "nfc"], excluded.Transports);
    }

    [Fact]
    public void Begin_refuses_a_short_challenge_or_an_origin_that_isnt_the_RP_IDs()
    {
        var verifier = Fido2WebAuthn.Create();

        Assert.Throws<ArgumentException>(() => verifier.BeginRegistration(new WebAuthnRegistrationBegin(Admin, User, [], new byte[15])));
        Assert.Throws<ArgumentException>(() => verifier.BeginRegistration(
            new WebAuthnRegistrationBegin(Admin with { Origin = "https://elsewhere.test" }, User, [], new byte[32])));
        Assert.Throws<ArgumentException>(() => verifier.BeginRegistration(
            new WebAuthnRegistrationBegin(Admin with { Origin = "https://admin.gatekeep.test/path" }, User, [], new byte[32])));
        Assert.Throws<ArgumentException>(() => verifier.BeginRegistration(
            new WebAuthnRegistrationBegin(Admin, User with { Handle = new byte[65] }, [], new byte[32])));
    }

    private static Task<WebAuthnRegistrationResult> FinishAsync(
        IWebAuthnVerifier verifier,
        WebAuthnRelyingParty party,
        byte[] challenge,
        SoftwareAuthenticator authenticator,
        string rpId,
        string origin,
        AttestationTweaks? tweaks = null,
        IReadOnlyList<WebAuthnCredentialDescriptor>? exclude = null)
    {
        using var body = JsonDocument.Parse(authenticator.Attest(rpId, Base64Url.EncodeToString(challenge), origin, tweaks));
        var response = body.RootElement.GetProperty("response");
        var attestation = new WebAuthnAttestation(
            authenticator.CredentialId,
            Base64Url.DecodeFromChars(response.GetProperty("clientDataJSON").GetString()!),
            Base64Url.DecodeFromChars(response.GetProperty("attestationObject").GetString()!),
            ["usb"]);
        return verifier.FinishRegistrationAsync(
            new WebAuthnRegistrationFinish(party, User, exclude ?? [], SHA256.HashData(challenge), attestation),
            Cancellation);
    }
}
