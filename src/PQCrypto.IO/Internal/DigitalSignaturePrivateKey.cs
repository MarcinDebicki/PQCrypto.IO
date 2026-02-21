namespace PQCrypto.IO.Internal;

public sealed record class DigitalSignaturePrivateKey : AMemoryLocked, IDigitalSignaturePrivateKey
{
    public DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    public LibVersion LibVersion { get; }

    public DigitalSignaturePrivateKey(DigitalSignatureAlgorithm algorithmVariant, LibVersion libVersion, byte[] value)
    {
        this.DigitalSignatureAlgorithm = algorithmVariant;
        this.LibVersion = libVersion;
        Value = value;
    }
}
