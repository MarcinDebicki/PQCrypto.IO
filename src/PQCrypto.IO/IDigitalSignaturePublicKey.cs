namespace PQCrypto.IO;

public interface IDigitalSignaturePublicKey
{
    DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    LibVersion LibVersion { get; }
    byte[] Value { get; }
}
