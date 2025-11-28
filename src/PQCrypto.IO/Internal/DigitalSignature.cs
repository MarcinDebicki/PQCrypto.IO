namespace PQCrypto.IO.Internal;

public sealed record class DigitalSignature : IDigitalSignature
{
    public byte[] Value { get; }

    public DigitalSignature(byte[] value)
    {
        this.Value = value;
    }
}
