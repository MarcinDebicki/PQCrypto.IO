namespace PQCrypto.IO.Internal;

public sealed record class DigitalSignaturePublicKey : IDigitalSignaturePublicKey
{
    public DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; }
    public byte[] Value { get; }

    public DigitalSignaturePublicKey(DigitalSignatureAlgorithm algorithmVariant, byte[] value)
    {
        this.DigitalSignatureAlgorithm = algorithmVariant;

        this.Value = value;
    }
}
