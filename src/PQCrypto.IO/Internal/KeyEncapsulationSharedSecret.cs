namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationSharedSecret : IKeyEncapsulationSharedSecret
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public MemorySafe Value { get; }

    public KeyEncapsulationSharedSecret(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm, LibVersion libVersion, MemorySafe value)
    {
        this.KeyEncapsulationAlgorithm = keyEncapsulationAlgorithm;
        this.LibVersion = libVersion;
        this.Value = value;
    }
}
