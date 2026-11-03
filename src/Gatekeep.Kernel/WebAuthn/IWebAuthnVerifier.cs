namespace Gatekeep.Kernel.WebAuthn;

/// <summary>
/// WebAuthn ceremonies (AD-31, AD-24), behind one port so that no module holds a WebAuthn library
/// and every call says which Relying Party it is for. The adapter is stateless: it keeps no RP
/// ID, origin or challenge between calls, and knows no User or Admin types. Registration asks
/// for no attestation, requires user verification, prefers a resident key, and allows ES256 and
/// RS256 only.
/// </summary>
public interface IWebAuthnVerifier
{
    /// <summary>
    /// The creation options for <c>navigator.credentials.create</c>, carrying the caller's
    /// <see cref="WebAuthnRegistrationBegin.Challenge"/>, which the caller stores (as its SHA-256)
    /// until the registration finishes.
    /// </summary>
    /// <exception cref="ArgumentException">The request is malformed, such as a challenge under 16 bytes or a user handle over 64.</exception>
    WebAuthnCreationOptions BeginRegistration(WebAuthnRegistrationBegin request);

    /// <summary>
    /// Verifies an attestation response against the Relying Party and challenge in
    /// <paramref name="request"/>. A response the ceremony refuses is a refused result, never an
    /// exception: one for another RP ID or origin, a cross-origin one, one without user
    /// verification, one whose challenge isn't the stored one, and one returning an excluded
    /// credential.
    /// </summary>
    Task<WebAuthnRegistrationResult> FinishRegistrationAsync(WebAuthnRegistrationFinish request, CancellationToken cancellationToken);
}

/// <summary>
/// The Relying Party a ceremony is for, given on every call: its RP ID (a hostname, never a
/// URL), its display name, and the one origin a response must come from, exactly.
/// </summary>
public sealed record WebAuthnRelyingParty(string Id, string Name, string Origin);

/// <summary>
/// The account a credential is registered to. <see cref="Handle"/> is the opaque WebAuthn user
/// handle, 1 to 64 bytes, never an internal ID; the names are what an authenticator shows.
/// </summary>
public sealed record WebAuthnUser(byte[] Handle, string Name, string DisplayName);

/// <summary>
/// One registration's start. <see cref="ExcludeCredentials"/> are the account's existing
/// credentials, with the transports they reported, so an authenticator that already holds one of
/// them isn't used again.
/// </summary>
public sealed record WebAuthnRegistrationBegin(
    WebAuthnRelyingParty RelyingParty,
    WebAuthnUser User,
    IReadOnlyList<WebAuthnCredentialDescriptor> ExcludeCredentials,
    byte[] Challenge);

/// <summary>
/// One registration's end. <see cref="ChallengeSha256"/> is the stored challenge, as it is
/// stored: the SHA-256 of the bytes <see cref="IWebAuthnVerifier.BeginRegistration"/> sent.
/// </summary>
public sealed record WebAuthnRegistrationFinish(
    WebAuthnRelyingParty RelyingParty,
    WebAuthnUser User,
    IReadOnlyList<WebAuthnCredentialDescriptor> ExcludeCredentials,
    byte[] ChallengeSha256,
    WebAuthnAttestation Attestation);

/// <summary>
/// An attestation response from the browser, decoded from base64url: the credential's raw ID,
/// the client data JSON, the attestation object and the transports the browser reported.
/// </summary>
public sealed record WebAuthnAttestation(
    byte[] CredentialId,
    byte[] ClientDataJson,
    byte[] AttestationObject,
    IReadOnlyList<string> Transports);

/// <summary>A public key credential parameter: its type, always <c>public-key</c>, and its COSE algorithm.</summary>
public sealed record WebAuthnPublicKeyParameter(string Type, int Algorithm);

/// <summary>An existing credential the authenticator mustn't hold: its ID and the transports it reported.</summary>
public sealed record WebAuthnCredentialDescriptor(string Type, byte[] Id, IReadOnlyList<string> Transports);

/// <summary>
/// The creation options as plain data, in WebAuthn's own terms: <c>rp</c>, <c>user</c>,
/// <c>challenge</c>, <c>pubKeyCredParams</c>, <c>timeout</c>, <c>attestation</c>,
/// <c>authenticatorSelection</c> and <c>excludeCredentials</c>.
/// </summary>
public sealed record WebAuthnCreationOptions(
    WebAuthnRelyingParty RelyingParty,
    WebAuthnUser User,
    byte[] Challenge,
    IReadOnlyList<WebAuthnPublicKeyParameter> PublicKeyParameters,
    uint TimeoutMilliseconds,
    string Attestation,
    string ResidentKey,
    string UserVerification,
    IReadOnlyList<WebAuthnCredentialDescriptor> ExcludeCredentials);

/// <summary>
/// A verified credential, as plain data: its ID, its COSE public key, its signature counter,
/// its authenticator's AAGUID, the transports reported, and whether the authenticator data's UV
/// flag was set. Registration requires it, so a verified credential always has it.
/// </summary>
public sealed record WebAuthnRegisteredCredential(
    byte[] CredentialId,
    byte[] PublicKey,
    uint SignCount,
    Guid Aaguid,
    IReadOnlyList<string> Transports,
    bool UserVerified);

/// <summary>Why a registration was refused. A fixed set, so nothing from the response reaches a log.</summary>
public enum WebAuthnRefusal
{
    /// <summary>The response couldn't be parsed, or is inconsistent with itself.</summary>
    Malformed,

    /// <summary>The client data isn't a <c>webauthn.create</c>.</summary>
    WrongType,

    /// <summary>The client data's challenge isn't the stored one.</summary>
    ChallengeMismatch,

    /// <summary>The client data's origin isn't exactly the Relying Party's origin.</summary>
    OriginMismatch,

    /// <summary>The client data says <c>crossOrigin</c>, or names a top origin.</summary>
    CrossOrigin,

    /// <summary>The authenticator data is for another RP ID.</summary>
    RpIdMismatch,

    /// <summary>The user wasn't present, or wasn't verified.</summary>
    UserNotVerified,

    /// <summary>The credential's algorithm isn't ES256 or RS256.</summary>
    AlgorithmNotAllowed,

    /// <summary>The authenticator returned a credential that was excluded.</summary>
    ExcludedCredential,

    /// <summary>Verification failed for another reason, such as a bad attestation statement.</summary>
    Invalid,
}

/// <summary>A registration's outcome: the credential, or why it was refused.</summary>
public sealed record WebAuthnRegistrationResult
{
    private WebAuthnRegistrationResult(WebAuthnRegisteredCredential? credential, WebAuthnRefusal? refusal)
    {
        Credential = credential;
        Refusal = refusal;
    }

    /// <summary>The verified credential, when the ceremony passed.</summary>
    public WebAuthnRegisteredCredential? Credential { get; }

    /// <summary>Why it didn't, when it didn't.</summary>
    public WebAuthnRefusal? Refusal { get; }

    public bool Verified => Credential is not null;

    public static WebAuthnRegistrationResult Registered(WebAuthnRegisteredCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        return new WebAuthnRegistrationResult(credential, null);
    }

    public static WebAuthnRegistrationResult Refused(WebAuthnRefusal refusal) => new(null, refusal);
}
