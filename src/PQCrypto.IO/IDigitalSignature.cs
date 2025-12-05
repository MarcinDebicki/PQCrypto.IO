namespace PQCrypto.IO;

public interface IDigitalSignature
{
    public DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public byte[] Value { get; }
}
