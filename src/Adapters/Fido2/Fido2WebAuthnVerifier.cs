using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Gatekeep.Kernel.WebAuthn;

namespace Gatekeep.Adapters.Fido2;

/// <summary>Makes the Kernel <see cref="IWebAuthnVerifier"/> over fido2-net-lib, for a host's composition root.</summary>
public static class Fido2WebAuthn
{
    /// <summary>
    /// The verifier. It holds nothing: each call builds its own <c>Fido2</c> instance from the
    /// Relying Party it is given, so one verifier serves every RP ID and origin.
    /// </summary>
    public static IWebAuthnVerifier Create() => new Fido2WebAuthnVerifier();
}

/// <summary>
/// <see cref="IWebAuthnVerifier"/> over fido2-net-lib, stateless by construction: no field, and a
/// fresh <c>Fido2</c> and <c>Fido2Configuration</c> per call. Before the library verifies a
/// response, the client data is checked here too, exactly: its type, an origin equal to the
/// Relying Party's origin byte for byte (the library compares case-insensitively), no
/// <c>crossOrigin</c> and no <c>topOrigin</c>, and a challenge whose SHA-256 is the stored one,
/// compared in constant time.
/// </summary>
internal sealed class Fido2WebAuthnVerifier : IWebAuthnVerifier
{
    /// <summary>The shortest challenge WebAuthn allows a Relying Party to send (§13.4.3).</summary>
    private const int MinChallengeBytes = 16;

    private const int MaxUserHandleBytes = 64;

    /// <summary>How long the browser waits for the authenticator, the same as the challenge's lifetime.</summary>
    private const uint TimeoutMilliseconds = 300_000;

    private const string PublicKey = "public-key";

    private const string Create = "webauthn.create";

    /// <summary>ES256 first, as external authenticators support it, then RS256 for platforms that need it.</summary>
    private static readonly IReadOnlyList<PubKeyCredParam> Parameters = [PubKeyCredParam.ES256, PubKeyCredParam.RS256];

    private static readonly IReadOnlyDictionary<string, AuthenticatorTransport> TransportNames =
        new Dictionary<string, AuthenticatorTransport>(StringComparer.Ordinal)
        {
            ["usb"] = AuthenticatorTransport.Usb,
            ["nfc"] = AuthenticatorTransport.Nfc,
            ["ble"] = AuthenticatorTransport.Ble,
            ["smart-card"] = AuthenticatorTransport.SmartCard,
            ["hybrid"] = AuthenticatorTransport.Hybrid,
            ["internal"] = AuthenticatorTransport.Internal,
        };

    public WebAuthnCreationOptions BeginRegistration(WebAuthnRegistrationBegin request)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireRelyingParty(request.RelyingParty);
        RequireUser(request.User);
        ArgumentNullException.ThrowIfNull(request.ExcludeCredentials);
        ArgumentNullException.ThrowIfNull(request.Challenge);
        if (request.Challenge.Length < MinChallengeBytes)
        {
            throw new ArgumentException($"A challenge is at least {MinChallengeBytes} bytes.", nameof(request));
        }

        var config = Configuration(request.RelyingParty);
        var options = Options(config, request.User, request.ExcludeCredentials, request.Challenge);

        return new WebAuthnCreationOptions(
            new WebAuthnRelyingParty(options.Rp.Id, options.Rp.Name, request.RelyingParty.Origin),
            request.User,
            options.Challenge,
            [.. options.PubKeyCredParams.Select(p => new WebAuthnPublicKeyParameter(PublicKey, (int)p.Alg))],
            (uint)options.Timeout,
            "none",
            "preferred",
            "required",
            [.. options.ExcludeCredentials.Select(d => new WebAuthnCredentialDescriptor(
                PublicKey,
                d.Id,
                [.. (d.Transports ?? []).Select(TransportName).OfType<string>()]))]);
    }

    public async Task<WebAuthnRegistrationResult> FinishRegistrationAsync(WebAuthnRegistrationFinish request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireRelyingParty(request.RelyingParty);
        RequireUser(request.User);
        ArgumentNullException.ThrowIfNull(request.ExcludeCredentials);
        ArgumentNullException.ThrowIfNull(request.ChallengeSha256);
        ArgumentNullException.ThrowIfNull(request.Attestation);

        var attestation = request.Attestation;
        if (attestation.CredentialId is not { Length: > 0 } || attestation.ClientDataJson is not { Length: > 0 }
            || attestation.AttestationObject is not { Length: > 0 } || request.ChallengeSha256.Length != SHA256.HashSizeInBytes)
        {
            return WebAuthnRegistrationResult.Refused(WebAuthnRefusal.Malformed);
        }

        if (ClientData(attestation.ClientDataJson, request.RelyingParty, request.ChallengeSha256, out var challenge) is { } refusal)
        {
            return WebAuthnRegistrationResult.Refused(refusal);
        }

        var config = Configuration(request.RelyingParty);
        var excluded = request.ExcludeCredentials;
        RegisteredPublicKeyCredential credential;
        bool userVerified;
        try
        {
            var raw = new AuthenticatorAttestationRawResponse
            {
                Id = Base64Url.EncodeToString(attestation.CredentialId),
                RawId = attestation.CredentialId,
                Type = PublicKeyCredentialType.PublicKey,
                Response = new AuthenticatorAttestationRawResponse.AttestationResponse
                {
                    AttestationObject = attestation.AttestationObject,
                    ClientDataJson = attestation.ClientDataJson,
                    Transports = Transports(attestation.Transports),
                },
                ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
            };

            // Parsed here too, for the UV flag the verified credential doesn't carry.
            userVerified = AuthenticatorAttestationResponse.Parse(raw).AttestationObject.AuthData.UserVerified;

            credential = await new Fido2NetLib.Fido2(config).MakeNewCredentialAsync(
                new MakeNewCredentialParams
                {
                    AttestationResponse = raw,
                    OriginalOptions = Options(config, request.User, excluded, challenge),
                    IsCredentialIdUniqueToUserCallback = (args, _) =>
                        Task.FromResult(!excluded.Any(d => d.Id.AsSpan().SequenceEqual(args.CredentialId))),
                },
                cancellationToken);
        }
        catch (Fido2VerificationException e)
        {
            return WebAuthnRegistrationResult.Refused(Refusal(e.Code));
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // Attacker-controlled bytes the library didn't wrap (CBOR, ASN.1, overflow, format and
            // the rest): a malformed response, never a fault. Only cancellation passes.
            return WebAuthnRegistrationResult.Refused(WebAuthnRefusal.Malformed);
        }

        return WebAuthnRegistrationResult.Registered(new WebAuthnRegisteredCredential(
            credential.Id,
            credential.PublicKey,
            credential.SignCount,
            credential.AaGuid,
            [.. (credential.Transports ?? []).Select(TransportName).OfType<string>().Distinct(StringComparer.Ordinal)],
            userVerified));
    }

    /// <summary>
    /// The client data's own checks, before the library's: a refusal, or null and the challenge
    /// the browser signed over, which is the one whose SHA-256 was stored.
    /// </summary>
    private static WebAuthnRefusal? ClientData(byte[] json, WebAuthnRelyingParty relyingParty, byte[] storedHash, out byte[] challenge)
    {
        challenge = [];
        string? type;
        string? origin;
        string? encodedChallenge;
        bool crossOrigin;
        bool topOrigin;
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return WebAuthnRefusal.Malformed;
            }

            type = StringProperty(root, "type");
            origin = StringProperty(root, "origin");
            encodedChallenge = StringProperty(root, "challenge");
            crossOrigin = root.TryGetProperty("crossOrigin", out var cross) && cross.ValueKind != JsonValueKind.False;
            topOrigin = root.TryGetProperty("topOrigin", out var top) && top.ValueKind != JsonValueKind.Null;
        }
        catch (JsonException)
        {
            return WebAuthnRefusal.Malformed;
        }

        if (type != Create)
        {
            return WebAuthnRefusal.WrongType;
        }

        // Absent is same-origin; anything but false, true included, is cross-origin.
        if (crossOrigin || topOrigin)
        {
            return WebAuthnRefusal.CrossOrigin;
        }

        if (!string.Equals(origin, relyingParty.Origin, StringComparison.Ordinal))
        {
            return WebAuthnRefusal.OriginMismatch;
        }

        if (encodedChallenge is null)
        {
            return WebAuthnRefusal.Malformed;
        }

        byte[] decoded;
        try
        {
            decoded = Base64Url.DecodeFromChars(encodedChallenge);
        }
        catch (FormatException)
        {
            return WebAuthnRefusal.Malformed;
        }

        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(decoded), storedHash))
        {
            return WebAuthnRefusal.ChallengeMismatch;
        }

        challenge = decoded;
        return null;
    }

    private static string? StringProperty(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>A configuration for this call's Relying Party alone. It is never kept.</summary>
    private static Fido2Configuration Configuration(WebAuthnRelyingParty relyingParty) => new()
    {
        RPID = relyingParty.Id,
        RPName = relyingParty.Name,
        Origins = new HashSet<string>(StringComparer.Ordinal) { relyingParty.Origin },
        AllowCrossOriginRequests = false,
        Timeout = TimeoutMilliseconds,
    };

    private static CredentialCreateOptions Options(
        Fido2Configuration config,
        WebAuthnUser user,
        IReadOnlyList<WebAuthnCredentialDescriptor> excluded,
        byte[] challenge) =>
        CredentialCreateOptions.Create(
            config,
            challenge,
            new Fido2User { Id = user.Handle, Name = user.Name, DisplayName = user.DisplayName },
            new AuthenticatorSelection
            {
                ResidentKey = ResidentKeyRequirement.Preferred,
                UserVerification = UserVerificationRequirement.Required,
            },
            AttestationConveyancePreference.None,
            [.. excluded.Select(d => new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PublicKey, d.Id, NullIfEmpty(Transports(d.Transports))))],
            extensions: null,
            Parameters);

    private static WebAuthnRefusal Refusal(Fido2ErrorCode code) => code switch
    {
        Fido2ErrorCode.InvalidRpidHash => WebAuthnRefusal.RpIdMismatch,
        Fido2ErrorCode.UserVerificationRequirementNotMet or Fido2ErrorCode.UserPresentFlagNotSet => WebAuthnRefusal.UserNotVerified,
        Fido2ErrorCode.CredentialAlgorithmRequirementNotMet or Fido2ErrorCode.UnimplementedAlgorithm => WebAuthnRefusal.AlgorithmNotAllowed,
        Fido2ErrorCode.NonUniqueCredentialId => WebAuthnRefusal.ExcludedCredential,
        Fido2ErrorCode.InvalidAuthenticatorResponseOrigin or Fido2ErrorCode.MissingAuthenticatorResponseOrigin => WebAuthnRefusal.OriginMismatch,
        Fido2ErrorCode.CrossOriginRequestNotAllowed or Fido2ErrorCode.InvalidAuthenticatorResponseTopOrigin => WebAuthnRefusal.CrossOrigin,
        Fido2ErrorCode.InvalidAuthenticatorResponseChallenge or Fido2ErrorCode.MissingAuthenticatorResponseChallenge => WebAuthnRefusal.ChallengeMismatch,
        Fido2ErrorCode.InvalidAttestationObject or Fido2ErrorCode.MalformedAttestationObject or Fido2ErrorCode.MissingAttestationObject
            or Fido2ErrorCode.InvalidAuthenticatorResponse or Fido2ErrorCode.MalformedAuthenticatorResponse
            or Fido2ErrorCode.InvalidAttestationResponse or Fido2ErrorCode.InvalidAuthenticatorData
            or Fido2ErrorCode.MissingAuthenticatorData or Fido2ErrorCode.InvalidAttestedCredentialData
            or Fido2ErrorCode.AttestedCredentialDataFlagNotSet or Fido2ErrorCode.InvalidCredentialPublicKey => WebAuthnRefusal.Malformed,
        _ => WebAuthnRefusal.Invalid,
    };

    private static AuthenticatorTransport[]? NullIfEmpty(AuthenticatorTransport[] transports) =>
        transports.Length == 0 ? null : transports;

    private static AuthenticatorTransport[] Transports(IReadOnlyList<string>? names) =>
        [.. (names ?? []).Where(n => n is not null && TransportNames.ContainsKey(n)).Select(n => TransportNames[n]).Distinct()];

    private static string? TransportName(AuthenticatorTransport transport) =>
        TransportNames.FirstOrDefault(p => p.Value == transport).Key;

    private static void RequireRelyingParty(WebAuthnRelyingParty relyingParty)
    {
        ArgumentNullException.ThrowIfNull(relyingParty);
        ArgumentException.ThrowIfNullOrWhiteSpace(relyingParty.Id);
        ArgumentException.ThrowIfNullOrWhiteSpace(relyingParty.Name);
        ArgumentException.ThrowIfNullOrWhiteSpace(relyingParty.Origin);

        // The RP ID is a host, never a URL; the origin is a serialized origin whose host is the RP ID.
        if (!Uri.TryCreate(relyingParty.Origin, UriKind.Absolute, out var origin)
            || !string.Equals(origin.GetLeftPart(UriPartial.Authority), relyingParty.Origin, StringComparison.Ordinal)
            || !string.Equals(origin.IdnHost, relyingParty.Id, StringComparison.Ordinal))
        {
            throw new ArgumentException("The origin must be a serialized origin whose host is the RP ID.", nameof(relyingParty));
        }
    }

    private static void RequireUser(WebAuthnUser user)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(user.Handle);
        ArgumentNullException.ThrowIfNull(user.Name);
        ArgumentNullException.ThrowIfNull(user.DisplayName);
        if (user.Handle.Length is < 1 or > MaxUserHandleBytes)
        {
            throw new ArgumentException($"A user handle is 1 to {MaxUserHandleBytes} bytes.", nameof(user));
        }
    }
}
