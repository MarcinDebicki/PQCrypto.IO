namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationPrivateKey : IKeyEncapsulationPrivateKey
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public byte[] Value { get; }

    public KeyEncapsulationPrivateKey(KeyEncapsulationAlgorithm algorithmVariant, byte[] value)
    {
        this.KeyEncapsulationAlgorithm = algorithmVariant;
        this.Value = value;
    }
}
