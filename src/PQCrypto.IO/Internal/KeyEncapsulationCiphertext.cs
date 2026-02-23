namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationCiphertext : IKeyEncapsulationCiphertext
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public byte[] Value { get; }

    public KeyEncapsulationCiphertext(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm, LibVersion libVersion, byte[] value)
    {
        this.KeyEncapsulationAlgorithm = keyEncapsulationAlgorithm;
        this.LibVersion = libVersion;
        this.Value = value;
    }
}
