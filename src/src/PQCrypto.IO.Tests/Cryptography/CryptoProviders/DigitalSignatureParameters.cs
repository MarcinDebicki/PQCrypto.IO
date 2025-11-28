namespace PQCrypto.IO.Tests.Cryptography.CryptoProviders;

public sealed class DigitalSignatureParameters
{
    public required DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; init; }
    public required int LengthPublicKey { get; init; }
    public required int LengthSecretKey { get; init; }
    public required int LengthSignature { get; init; }

    /// <summary>
    ///     The length of the signature may be shorter
    /// </summary>
    public required bool ShorterSignature { get; init; }
}
