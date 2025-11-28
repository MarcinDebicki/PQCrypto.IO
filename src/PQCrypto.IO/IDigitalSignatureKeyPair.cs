namespace PQCrypto.IO;

public interface IDigitalSignatureKeyPair
{
    DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; init; }
    IDigitalSignaturePrivateKey PrivateKey { get; init; }
    IDigitalSignaturePublicKey PublicKey { get; init; }
}
