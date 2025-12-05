namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationPublicKey : IKeyEncapsulationPublicKey
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public byte[] Value { get; }

    public KeyEncapsulationPublicKey(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm, LibVersion libVersion, byte[] value)
    {
        this.KeyEncapsulationAlgorithm = keyEncapsulationAlgorithm;
        this.LibVersion = libVersion;
        this.Value = value;
    }
}
