namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationPublicKey : IKeyEncapsulationPublicKey
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public byte[] Value { get; }

    public KeyEncapsulationPublicKey(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm, byte[] value, LibVersion libVersion)
    {
        this.KeyEncapsulationAlgorithm = keyEncapsulationAlgorithm;
        this.LibVersion = libVersion;
        this.Value = value;
    }
}
