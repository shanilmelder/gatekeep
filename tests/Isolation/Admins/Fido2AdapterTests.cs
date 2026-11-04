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
    private static readonly WebAuthnRelyingParty Admin = new("admin.gatekeep-admin.test", "Gatekeep", "https://admin.gatekeep-admin.test");

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
            Assert.Equal(("none", "required", "required"), (options.Attestation, options.ResidentKey, options.UserVerification));

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
    [InlineData("https://ADMIN.gatekeep-admin.test")]
    [InlineData("https://admin.gatekeep-admin.test:443")]
    [InlineData("https://admin.gatekeep-admin.test/")]
    [InlineData("http://admin.gatekeep-admin.test")]
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
            new WebAuthnRegistrationBegin(Admin with { Origin = "https://admin.gatekeep-admin.test/path" }, User, [], new byte[32])));
        Assert.Throws<ArgumentException>(() => verifier.BeginRegistration(
            new WebAuthnRegistrationBegin(Admin, User with { Handle = new byte[65] }, [], new byte[32])));
    }

    // Story 1.23: the assertion ceremony, with the same per-call Relying Party and no state.

    [Fact]
    public async Task Assertion_verifies_against_each_Relying_Party_it_is_given_per_call()
    {
        var verifier = Fido2WebAuthn.Create();
        using var authenticator = new SoftwareAuthenticator { UserHandle = User.Handle };

        foreach (var party in new[] { Admin, Other, Admin })
        {
            var stored = await RegisteredAsync(verifier, party, authenticator) with { SignCount = authenticator.Counter };
            var challenge = RandomNumberGenerator.GetBytes(32);

            var options = verifier.BeginAssertion(new WebAuthnAssertionBegin(party, challenge));
            Assert.Equal((party.Id, "required", 300_000u), (options.RpId, options.UserVerification, options.TimeoutMilliseconds));
            Assert.Equal(challenge, options.Challenge);
            Assert.Empty(options.AllowCredentials);

            var result = await AssertAsync(verifier, party, challenge, authenticator, stored, party.Id, party.Origin);
            Assert.True(result.Verified, $"{party.Id}: {result.Refusal}");
            Assert.Equal(authenticator.Counter, result.SignCount);
            Assert.True(result.UserVerified);
        }
    }

    public static TheoryData<string, WebAuthnRefusal> AssertionRefusals => new()
    {
        { "another RP ID", WebAuthnRefusal.RpIdMismatch },
        { "another origin", WebAuthnRefusal.OriginMismatch },
        { "the origin in other case", WebAuthnRefusal.OriginMismatch },
        { "crossOrigin true", WebAuthnRefusal.CrossOrigin },
        { "a top origin", WebAuthnRefusal.CrossOrigin },
        { "no user verification", WebAuthnRefusal.UserNotVerified },
        { "no user presence", WebAuthnRefusal.UserNotVerified },
        { "a registration's type", WebAuthnRefusal.WrongType },
        { "another challenge", WebAuthnRefusal.ChallengeMismatch },
        { "no user handle", WebAuthnRefusal.UserHandleMismatch },
        { "another user handle", WebAuthnRefusal.UserHandleMismatch },
        { "a bad signature", WebAuthnRefusal.Invalid },
    };

    private static readonly Dictionary<string, AssertionTweaks> AssertionTweakCases = new()
    {
        { "another RP ID", new AssertionTweaks { RpId = Other.Id } },
        { "another origin", new AssertionTweaks { Origin = Other.Origin } },
        { "the origin in other case", new AssertionTweaks { Origin = "https://ADMIN.gatekeep-admin.test" } },
        { "crossOrigin true", new AssertionTweaks { CrossOrigin = true } },
        { "a top origin", new AssertionTweaks { TopOrigin = Admin.Origin } },
        { "no user verification", new AssertionTweaks { UserVerified = false } },
        { "no user presence", new AssertionTweaks { UserPresent = false } },
        { "a registration's type", new AssertionTweaks { Type = "webauthn.create" } },
        { "another challenge", new AssertionTweaks { Challenge = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32)) } },
        { "no user handle", new AssertionTweaks { OmitUserHandle = true } },
        { "another user handle", new AssertionTweaks { UserHandle = RandomNumberGenerator.GetBytes(64) } },
        { "a bad signature", new AssertionTweaks { OtherKey = true } },
    };

    [Theory]
    [MemberData(nameof(AssertionRefusals))]
    public async Task Assertion_the_ceremony_refuses_is_a_fixed_refusal(string assertion, WebAuthnRefusal refusal)
    {
        var verifier = Fido2WebAuthn.Create();
        using var authenticator = new SoftwareAuthenticator { UserHandle = User.Handle };
        var stored = await RegisteredAsync(verifier, Admin, authenticator);
        var challenge = RandomNumberGenerator.GetBytes(32);

        var result = await AssertAsync(verifier, Admin, challenge, authenticator, stored, Admin.Id, Admin.Origin, AssertionTweakCases[assertion]);

        Assert.Equal(refusal, result.Refusal);
        Assert.False(result.Verified);

        // Each of these comes before, or instead of, a verified signature.
        Assert.False(result.SignatureVerified);
    }

    [Fact]
    public async Task Only_a_counter_refusal_comes_after_the_signature()
    {
        var verifier = Fido2WebAuthn.Create();
        using var authenticator = new SoftwareAuthenticator { UserHandle = User.Handle };
        var stored = await RegisteredAsync(verifier, Admin, authenticator) with { SignCount = 7 };

        var forged = await AssertAsync(verifier, Admin, RandomNumberGenerator.GetBytes(32), authenticator, stored, Admin.Id, Admin.Origin, new AssertionTweaks { OtherKey = true, SignCount = 3 });
        var regressed = await AssertAsync(verifier, Admin, RandomNumberGenerator.GetBytes(32), authenticator, stored, Admin.Id, Admin.Origin, new AssertionTweaks { SignCount = 3 });
        var verified = await AssertAsync(verifier, Admin, RandomNumberGenerator.GetBytes(32), authenticator, stored, Admin.Id, Admin.Origin, new AssertionTweaks { SignCount = 8 });

        // A bad signature with a low counter is refused for the signature, not as a clone.
        Assert.Equal((WebAuthnRefusal.Invalid, false), (forged.Refusal!.Value, forged.SignatureVerified));
        Assert.Equal((WebAuthnRefusal.SignCountRegressed, true), (regressed.Refusal!.Value, regressed.SignatureVerified));
        Assert.True(verified.Verified);
        Assert.True(verified.SignatureVerified);
    }

    [Theory]
    [InlineData(0u, 0u, null)]
    [InlineData(0u, 1u, null)]
    [InlineData(7u, 8u, null)]
    [InlineData(7u, 7u, WebAuthnRefusal.SignCountRegressed)]
    [InlineData(7u, 3u, WebAuthnRefusal.SignCountRegressed)]
    [InlineData(7u, 0u, WebAuthnRefusal.SignCountRegressed)]
    public async Task Counter_must_advance_unless_both_are_0(uint stored, uint asserted, WebAuthnRefusal? refusal)
    {
        var verifier = Fido2WebAuthn.Create();
        using var authenticator = new SoftwareAuthenticator { UserHandle = User.Handle };
        var credential = await RegisteredAsync(verifier, Admin, authenticator) with { SignCount = stored };
        var challenge = RandomNumberGenerator.GetBytes(32);

        var result = await AssertAsync(verifier, Admin, challenge, authenticator, credential, Admin.Id, Admin.Origin, new AssertionTweaks { SignCount = asserted });

        Assert.Equal(refusal, result.Refusal);
        if (refusal is null)
        {
            Assert.Equal(asserted, result.SignCount);
        }
    }

    [Fact]
    public async Task Assertion_for_another_credential_or_a_malformed_one_is_refused_never_thrown()
    {
        var verifier = Fido2WebAuthn.Create();
        using var authenticator = new SoftwareAuthenticator { UserHandle = User.Handle };
        using var other = new SoftwareAuthenticator { UserHandle = User.Handle };
        var stored = await RegisteredAsync(verifier, Admin, authenticator);
        var challenge = RandomNumberGenerator.GetBytes(32);

        // The stored credential isn't the one the response names.
        var crossed = await AssertAsync(verifier, Admin, challenge, other, stored, Admin.Id, Admin.Origin);
        Assert.Equal(WebAuthnRefusal.Invalid, crossed.Refusal);

        // Authenticator data and a signature that aren't what they claim: refused, not thrown.
        var garbage = await verifier.FinishAssertionAsync(
            new WebAuthnAssertionFinish(
                Admin,
                SHA256.HashData(challenge),
                new WebAuthnAssertion(
                    authenticator.CredentialId,
                    SoftwareAuthenticator.ClientData("webauthn.get", Base64Url.EncodeToString(challenge), Admin.Origin, null, null),
                    [1, 2, 3],
                    [4, 5, 6],
                    User.Handle),
                stored),
            Cancellation);
        Assert.False(garbage.Verified);
        Assert.Contains(garbage.Refusal, new WebAuthnRefusal?[] { WebAuthnRefusal.Malformed, WebAuthnRefusal.Invalid });
    }

    [Fact]
    public void Begin_assertion_refuses_a_short_challenge_or_an_origin_that_isnt_the_RP_IDs()
    {
        var verifier = Fido2WebAuthn.Create();

        Assert.Throws<ArgumentException>(() => verifier.BeginAssertion(new WebAuthnAssertionBegin(Admin, new byte[15])));
        Assert.Throws<ArgumentException>(() => verifier.BeginAssertion(new WebAuthnAssertionBegin(Admin with { Origin = "https://elsewhere.test" }, new byte[32])));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Backup_flags_are_read_and_a_changed_BE_is_refused(bool eligible, bool backedUp)
    {
        var verifier = Fido2WebAuthn.Create();
        using var authenticator = new SoftwareAuthenticator { UserHandle = User.Handle, BackupEligible = eligible, BackedUp = backedUp };

        var registered = await FinishAsync(verifier, Admin, RandomNumberGenerator.GetBytes(32), authenticator, Admin.Id, Admin.Origin);
        Assert.True(registered.Verified, $"{registered.Refusal}");
        Assert.Equal((eligible, backedUp), (registered.Credential!.BackupEligible, registered.Credential.BackedUp));

        // BS may change between assertions, and the result says the new one.
        var stored = await RegisteredAsync(verifier, Admin, authenticator) with { SignCount = authenticator.Counter };
        var flipped = await AssertAsync(
            verifier, Admin, RandomNumberGenerator.GetBytes(32), authenticator, stored, Admin.Id, Admin.Origin,
            new AssertionTweaks { BackedUp = eligible && !backedUp });
        Assert.True(flipped.Verified, $"{flipped.Refusal}");
        Assert.Equal(eligible && !backedUp, flipped.BackedUp);

        // BE never changes for a credential: an assertion with the other one isn't this credential's.
        var changed = await AssertAsync(
            verifier, Admin, RandomNumberGenerator.GetBytes(32), authenticator, stored with { SignCount = authenticator.Counter }, Admin.Id, Admin.Origin,
            new AssertionTweaks { BackupEligible = !eligible, BackedUp = false });
        Assert.Equal(WebAuthnRefusal.Invalid, changed.Refusal);
        Assert.False(changed.SignatureVerified);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task An_unknown_stored_BE_is_reported_not_compared(bool eligible)
    {
        var verifier = Fido2WebAuthn.Create();
        using var authenticator = new SoftwareAuthenticator { UserHandle = User.Handle, BackupEligible = eligible };
        var stored = await RegisteredAsync(verifier, Admin, authenticator) with { SignCount = authenticator.Counter, BackupEligible = null };

        var result = await AssertAsync(verifier, Admin, RandomNumberGenerator.GetBytes(32), authenticator, stored, Admin.Id, Admin.Origin);

        Assert.True(result.Verified, $"{result.Refusal}");
        Assert.Equal(eligible, result.BackupEligible);
    }

    /// <summary>Registers <paramref name="authenticator"/> for <paramref name="party"/>, as stored: its ID, key and counter, and the user's handle.</summary>
    private static async Task<WebAuthnStoredCredential> RegisteredAsync(IWebAuthnVerifier verifier, WebAuthnRelyingParty party, SoftwareAuthenticator authenticator)
    {
        var registered = await FinishAsync(verifier, party, RandomNumberGenerator.GetBytes(32), authenticator, party.Id, party.Origin);
        Assert.True(registered.Verified, $"{registered.Refusal}");
        return new WebAuthnStoredCredential(registered.Credential!.CredentialId, registered.Credential.PublicKey, registered.Credential.SignCount, User.Handle, registered.Credential.BackupEligible);
    }

    private static Task<WebAuthnAssertionResult> AssertAsync(
        IWebAuthnVerifier verifier,
        WebAuthnRelyingParty party,
        byte[] challenge,
        SoftwareAuthenticator authenticator,
        WebAuthnStoredCredential stored,
        string rpId,
        string origin,
        AssertionTweaks? tweaks = null)
    {
        using var body = JsonDocument.Parse(authenticator.Assert(rpId, Base64Url.EncodeToString(challenge), origin, tweaks));
        var response = body.RootElement.GetProperty("response");
        var handle = response.GetProperty("userHandle");
        var assertion = new WebAuthnAssertion(
            authenticator.CredentialId,
            Base64Url.DecodeFromChars(response.GetProperty("clientDataJSON").GetString()!),
            Base64Url.DecodeFromChars(response.GetProperty("authenticatorData").GetString()!),
            Base64Url.DecodeFromChars(response.GetProperty("signature").GetString()!),
            handle.ValueKind == JsonValueKind.Null ? null : Base64Url.DecodeFromChars(handle.GetString()!));
        return verifier.FinishAssertionAsync(new WebAuthnAssertionFinish(party, SHA256.HashData(challenge), assertion, stored), Cancellation);
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
