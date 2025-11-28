namespace PQCrypto.IO;

public interface IDigitalSignaturePrivateKey
{
    DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    byte[] Value { get; }
}
