namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationCiphertext : IKeyEncapsulationCiphertext
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public byte[] Value { get; }

    public KeyEncapsulationCiphertext(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm, byte[] value)
    {
        this.KeyEncapsulationAlgorithm = keyEncapsulationAlgorithm;
        this.Value = value;
    }
}
