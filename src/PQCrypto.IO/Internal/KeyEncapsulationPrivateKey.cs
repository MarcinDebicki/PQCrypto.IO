namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationPrivateKey : AMemoryLocked, IKeyEncapsulationPrivateKey
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public LibVersion LibVersion { get; }

    public KeyEncapsulationPrivateKey(KeyEncapsulationAlgorithm algorithmVariant, LibVersion libVersion, byte[] value)
    {
        this.KeyEncapsulationAlgorithm = algorithmVariant;
        this.LibVersion = libVersion;
        Value = value;
    }
}
