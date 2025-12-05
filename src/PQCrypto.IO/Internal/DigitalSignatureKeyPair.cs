namespace PQCrypto.IO.Internal;

public sealed record class DigitalSignatureKeyPair : IDigitalSignatureKeyPair
{
    public required DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; init; }
    public required LibVersion LibVersion { get; init; }
    public required IDigitalSignaturePrivateKey PrivateKey { get; init; }
    public required IDigitalSignaturePublicKey PublicKey { get; init; }

    public DigitalSignatureKeyPair()
    {
    }
}
