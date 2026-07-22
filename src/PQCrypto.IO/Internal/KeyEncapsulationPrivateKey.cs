namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationPrivateKey : IKeyEncapsulationPrivateKey
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public MemorySafe Value { get; private set; }

    public KeyEncapsulationPrivateKey(KeyEncapsulationAlgorithm algorithmVariant, LibVersion libVersion, MemorySafe value)
    {
        this.KeyEncapsulationAlgorithm = algorithmVariant;
        this.LibVersion = libVersion;
        this.Value = value;
    }

    public void Dispose()
    {
        this.Value.Dispose();
        this.Value = null;
    }
}
