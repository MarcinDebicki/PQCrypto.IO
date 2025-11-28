namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationSharedSecret : IKeyEncapsulationSharedSecret
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public byte[] Value { get; }

    public KeyEncapsulationSharedSecret(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm, byte[] value)
    {
        this.KeyEncapsulationAlgorithm = keyEncapsulationAlgorithm;

        this.Value = value;
    }
}
