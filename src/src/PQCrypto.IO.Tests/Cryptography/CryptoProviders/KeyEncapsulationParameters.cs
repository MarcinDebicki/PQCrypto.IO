namespace PQCrypto.IO.Tests.Cryptography.CryptoProviders;

public sealed class KeyEncapsulationParameters
{
    public required KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; init; }
    public required int LengthCiphertext { get; init; }
    public required int LengthPublicKey { get; init; }
    public required int LengthSecretKey { get; init; }
    public required int LengthSharedSecret { get; init; }
}
