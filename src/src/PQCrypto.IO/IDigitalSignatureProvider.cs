namespace PQCrypto.IO;

public interface IDigitalSignatureProvider
{
    DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    IDigitalSignatureKeyPair GenerateKeyPair();
    IDigitalSignature Sign(in IMessage message, in IDigitalSignaturePrivateKey privateKey);
    bool Verify(in IMessage message, in IDigitalSignature digitalSignature, in IDigitalSignaturePublicKey publicKey);
}
