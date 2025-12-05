namespace PQCrypto.IO.Internal;

public sealed record class DigitalSignaturePublicKey : IDigitalSignaturePublicKey
{
    public DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public byte[] Value { get; }

    public DigitalSignaturePublicKey(DigitalSignatureAlgorithm algorithmVariant, byte[] value, LibVersion libVersion)
    {
        this.DigitalSignatureAlgorithm = algorithmVariant;
        this.LibVersion = libVersion;
        this.Value = value;
    }
}
