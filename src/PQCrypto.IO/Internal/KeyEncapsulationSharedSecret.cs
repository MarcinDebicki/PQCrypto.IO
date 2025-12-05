namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationSharedSecret : IKeyEncapsulationSharedSecret
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public LibVersion LibVersion { get; }
    public byte[] Value { get; }

    public KeyEncapsulationSharedSecret(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm, LibVersion libVersion, byte[] value)
    {
        this.KeyEncapsulationAlgorithm = keyEncapsulationAlgorithm;
        this.LibVersion = libVersion;
        this.Value = value;
    }
}
