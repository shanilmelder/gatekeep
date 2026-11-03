namespace Gatekeep.Kernel.WebAuthn;

/// <summary>
/// WebAuthn ceremonies (AD-31, AD-24), behind one port so that no module holds a WebAuthn library
/// and every call says which Relying Party it is for. The adapter is stateless: it keeps no RP
/// ID, origin or challenge between calls, and knows no User or Admin types. Registration asks
/// for no attestation, requires user verification and a resident key (a discoverable credential,
/// so sign-in needs no username), and allows ES256 and RS256 only. An assertion requires user
/// verification and lists no credentials.
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

    /// <summary>
    /// The request options for <c>navigator.credentials.get</c>, carrying the caller's
    /// <see cref="WebAuthnAssertionBegin.Challenge"/>, which the caller stores (as its SHA-256)
    /// until the assertion finishes. <c>allowCredentials</c> is always empty: the credential is
    /// discoverable, so no credential ID goes to a caller who hasn't authenticated.
    /// </summary>
    /// <exception cref="ArgumentException">The request is malformed, such as a challenge under 16 bytes.</exception>
    WebAuthnRequestOptions BeginAssertion(WebAuthnAssertionBegin request);

    /// <summary>
    /// Verifies an assertion response against the Relying Party, the challenge and the stored
    /// credential in <paramref name="request"/>. A response the ceremony refuses is a refused
    /// result, never an exception: one for another RP ID or origin, a cross-origin one, one
    /// without user presence and verification, one whose challenge isn't the stored one, one
    /// whose user handle isn't the credential's owner's, one with a bad signature, and one whose
    /// signature counter doesn't advance past a non-zero stored one.
    /// </summary>
    Task<WebAuthnAssertionResult> FinishAssertionAsync(WebAuthnAssertionFinish request, CancellationToken cancellationToken);
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

/// <summary>One assertion's start: the Relying Party, and the challenge the caller made and stores.</summary>
public sealed record WebAuthnAssertionBegin(WebAuthnRelyingParty RelyingParty, byte[] Challenge);

/// <summary>
/// The request options as plain data, in WebAuthn's own terms: <c>challenge</c>, <c>rpId</c>,
/// <c>timeout</c>, <c>userVerification</c> and <c>allowCredentials</c>, which is always empty.
/// </summary>
public sealed record WebAuthnRequestOptions(
    byte[] Challenge,
    string RpId,
    uint TimeoutMilliseconds,
    string UserVerification,
    IReadOnlyList<WebAuthnCredentialDescriptor> AllowCredentials);

/// <summary>
/// One assertion's end. <see cref="ChallengeSha256"/> is the stored challenge, as it is stored:
/// the SHA-256 of the bytes <see cref="IWebAuthnVerifier.BeginAssertion"/> sent.
/// <see cref="Credential"/> is the stored credential the assertion's ID names.
/// </summary>
public sealed record WebAuthnAssertionFinish(
    WebAuthnRelyingParty RelyingParty,
    byte[] ChallengeSha256,
    WebAuthnAssertion Assertion,
    WebAuthnStoredCredential Credential);

/// <summary>
/// An assertion response from the browser, decoded from base64url: the credential's raw ID, the
/// client data JSON, the authenticator data, the signature and the user handle, which a
/// discoverable credential always returns, null when it was absent.
/// </summary>
public sealed record WebAuthnAssertion(
    byte[] CredentialId,
    byte[] ClientDataJson,
    byte[] AuthenticatorData,
    byte[] Signature,
    byte[]? UserHandle);

/// <summary>
/// A credential as the caller stored it at registration: its ID, its COSE public key, its last
/// signature counter, and the user handle of the account that owns it.
/// </summary>
public sealed record WebAuthnStoredCredential(byte[] CredentialId, byte[] PublicKey, uint SignCount, byte[] UserHandle);

/// <summary>Why a ceremony was refused. A fixed set, so nothing from the response reaches a log.</summary>
public enum WebAuthnRefusal
{
    /// <summary>The response couldn't be parsed, or is inconsistent with itself.</summary>
    Malformed,

    /// <summary>The client data isn't the ceremony's type: <c>webauthn.create</c> to register, <c>webauthn.get</c> to assert.</summary>
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

    /// <summary>Verification failed for another reason, such as a bad attestation statement or a bad signature.</summary>
    Invalid,

    /// <summary>
    /// An assertion's signature counter isn't greater than the stored one, and they aren't both
    /// 0: the sign of a cloned authenticator.
    /// </summary>
    SignCountRegressed,

    /// <summary>An assertion's user handle is absent, or isn't the stored credential's owner's.</summary>
    UserHandleMismatch,
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

/// <summary>
/// An assertion's outcome: when verified, the authenticator's new signature counter and whether
/// the UV flag was set (assertions require it, so a verified one always has it); when refused, why,
/// and whether the signature over the stored key had verified first. Only a refusal after a
/// verified signature proves the credential's holder made the response; any other could come from
/// anyone who knows a credential ID.
/// </summary>
public sealed record WebAuthnAssertionResult
{
    private WebAuthnAssertionResult(uint signCount, bool userVerified, WebAuthnRefusal? refusal, bool signatureVerified)
    {
        SignCount = signCount;
        UserVerified = userVerified;
        Refusal = refusal;
        SignatureVerified = signatureVerified;
    }

    /// <summary>The authenticator's new signature counter, when verified.</summary>
    public uint SignCount { get; }

    /// <summary>Whether the authenticator data's UV flag was set, when verified.</summary>
    public bool UserVerified { get; }

    /// <summary>Why it wasn't verified, when it wasn't.</summary>
    public WebAuthnRefusal? Refusal { get; }

    /// <summary>
    /// Whether the signature over the stored public key verified: always when verified, and for a
    /// refusal only when it came after the signature, such as <see cref="WebAuthnRefusal.SignCountRegressed"/>.
    /// </summary>
    public bool SignatureVerified { get; }

    public bool Verified => Refusal is null;

    public static WebAuthnAssertionResult Asserted(uint signCount, bool userVerified) => new(signCount, userVerified, null, signatureVerified: true);

    /// <summary>A refusal before the signature verified, or with no signature verified at all.</summary>
    public static WebAuthnAssertionResult Refused(WebAuthnRefusal refusal) => new(0, false, refusal, signatureVerified: false);

    /// <summary>A refusal of a response whose signature over the stored key had verified.</summary>
    public static WebAuthnAssertionResult RefusedAfterSignature(WebAuthnRefusal refusal) => new(0, false, refusal, signatureVerified: true);
}
