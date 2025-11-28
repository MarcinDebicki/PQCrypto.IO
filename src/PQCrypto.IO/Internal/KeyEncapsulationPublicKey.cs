namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationPublicKey : IKeyEncapsulationPublicKey
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public byte[] Value { get; }

    public KeyEncapsulationPublicKey(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm, byte[] value)
    {
        this.KeyEncapsulationAlgorithm = keyEncapsulationAlgorithm;

        this.Value = value;
    }
}
