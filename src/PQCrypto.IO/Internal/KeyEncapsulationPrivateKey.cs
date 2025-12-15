namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationPrivateKey : IKeyEncapsulationPrivateKey
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public byte[] Value { get; }

    public KeyEncapsulationPrivateKey(KeyEncapsulationAlgorithm algorithmVariant, byte[] value, LibVersion libVersion)
    {
        this.KeyEncapsulationAlgorithm = algorithmVariant;
        this.LibVersion = libVersion;
        this.Value = value;
    }
}
