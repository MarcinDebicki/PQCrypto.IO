namespace PQCrypto.IO;

public interface IDigitalSignaturePublicKey
{
    DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    byte[] Value { get; }
}
