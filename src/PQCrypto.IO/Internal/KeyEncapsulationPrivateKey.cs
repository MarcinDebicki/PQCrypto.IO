namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationPrivateKey : IKeyEncapsulationPrivateKey
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public MemorySafe Value { get; }

    public KeyEncapsulationPrivateKey(KeyEncapsulationAlgorithm algorithmVariant, LibVersion libVersion, MemorySafe value)
    {
        this.KeyEncapsulationAlgorithm = algorithmVariant;
        this.LibVersion = libVersion;
        this.Value = value;
    }
}
