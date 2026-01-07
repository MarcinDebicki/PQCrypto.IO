namespace PQCrypto.IO.Internal;

public sealed record class DigitalSignaturePrivateKey : IDigitalSignaturePrivateKey
{
    public DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public byte[] Value { get; }

    public DigitalSignaturePrivateKey(DigitalSignatureAlgorithm algorithmVariant, LibVersion libVersion, byte[] value)
    {
        this.DigitalSignatureAlgorithm = algorithmVariant;
        this.LibVersion = libVersion;
        this.Value = value;
    }
}
