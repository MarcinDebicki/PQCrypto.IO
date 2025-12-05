namespace PQCrypto.IO.Internal;

public sealed record class DigitalSignature : IDigitalSignature
{
    public DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public byte[] Value { get; }

    public DigitalSignature(DigitalSignatureAlgorithm digitalSignatureAlgorithm, LibVersion libVersion, byte[] value)
    {
        this.DigitalSignatureAlgorithm = digitalSignatureAlgorithm;
        this.LibVersion = libVersion;
        this.Value = value;
    }
}
