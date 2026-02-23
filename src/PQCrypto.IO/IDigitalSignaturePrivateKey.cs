namespace PQCrypto.IO;

public interface IDigitalSignaturePrivateKey
{
    DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    LibVersion LibVersion { get; }
    MemorySafe Value { get; }
}
