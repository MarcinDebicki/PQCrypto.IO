namespace PQCrypto.IO.Internal;

public sealed record class DigitalSignaturePrivateKey : IDigitalSignaturePrivateKey
{
    public DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    public byte[] Value { get; }

    public DigitalSignaturePrivateKey(DigitalSignatureAlgorithm algorithmVariant, byte[] value)
    {
        this.DigitalSignatureAlgorithm = algorithmVariant;
        this.Value = value;
    }
}
