using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Gatekeep.Modules.Keys.Core;

/// <summary>
/// Turns the PEM public half key custody returns into RSA modulus and exponent, by reading its DER
/// with <see cref="AsnReader"/>: the PEM import APIs are banned in <c>src/</c> (AD-10), and no RSA
/// object is made here. Only the public half ever reaches this code.
/// </summary>
internal static class RsaPublicKeys
{
    private const string RsaEncryption = "1.2.840.113549.1.1.1";

    private const string SubjectPublicKeyInfoLabel = "PUBLIC KEY";

    private const string Pkcs1Label = "RSA PUBLIC KEY";

    public static RSAParameters Parse(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);

        if (!PemEncoding.TryFind(pem, out var fields))
        {
            throw new FormatException("The public key isn't PEM.");
        }

        var label = pem[fields.Label];
        var der = Convert.FromBase64String(pem[fields.Base64Data]);

        try
        {
            return label switch
            {
                SubjectPublicKeyInfoLabel => FromSubjectPublicKeyInfo(der),
                Pkcs1Label => FromRsaPublicKey(der),
                _ => throw new FormatException("The PEM block isn't a public key."),
            };
        }
        catch (AsnContentException e)
        {
            throw new FormatException("The public key's DER is malformed.", e);
        }
    }

    /// <summary>SubjectPublicKeyInfo: <c>SEQUENCE { SEQUENCE { rsaEncryption, NULL }, BIT STRING RSAPublicKey }</c>.</summary>
    private static RSAParameters FromSubjectPublicKeyInfo(byte[] der)
    {
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var info = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        var algorithm = info.ReadSequence();
        if (algorithm.ReadObjectIdentifier() != RsaEncryption)
        {
            throw new FormatException("The public key isn't RSA.");
        }

        if (algorithm.HasData)
        {
            algorithm.ReadNull();
        }

        algorithm.ThrowIfNotEmpty();

        var key = info.ReadBitString(out var unused);
        info.ThrowIfNotEmpty();
        if (unused != 0)
        {
            throw new FormatException("The public key's bit string isn't whole bytes.");
        }

        return FromRsaPublicKey(key);
    }

    /// <summary>PKCS#1 RSAPublicKey: <c>SEQUENCE { modulus INTEGER, publicExponent INTEGER }</c>.</summary>
    private static RSAParameters FromRsaPublicKey(byte[] der)
    {
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var key = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        var modulus = Unsigned(key.ReadIntegerBytes().Span);
        var exponent = Unsigned(key.ReadIntegerBytes().Span);
        key.ThrowIfNotEmpty();

        if (modulus.Length == 0 || exponent.Length == 0)
        {
            throw new FormatException("The public key has an empty modulus or exponent.");
        }

        return new RSAParameters { Modulus = modulus, Exponent = exponent };
    }

    /// <summary>A DER INTEGER is signed: a leading zero only keeps a positive value positive.</summary>
    private static byte[] Unsigned(ReadOnlySpan<byte> value)
    {
        if (value.Length > 0 && (value[0] & 0x80) != 0)
        {
            throw new FormatException("The public key holds a negative integer.");
        }

        while (value.Length > 1 && value[0] == 0)
        {
            value = value[1..];
        }

        return value.Length == 1 && value[0] == 0 ? [] : value.ToArray();
    }
}
