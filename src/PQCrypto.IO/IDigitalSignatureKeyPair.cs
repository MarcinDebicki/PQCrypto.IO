namespace PQCrypto.IO;

public interface IDigitalSignatureKeyPair
{
    DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; init; }
    LibVersion LibVersion { get; }
    IDigitalSignaturePrivateKey PrivateKey { get; init; }
    IDigitalSignaturePublicKey PublicKey { get; init; }
}
