namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationCiphertext : AMemoryLocked, IKeyEncapsulationCiphertext
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    public LibVersion LibVersion { get; }

    public KeyEncapsulationCiphertext(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm, LibVersion libVersion, byte[] value)
    {
        this.KeyEncapsulationAlgorithm = keyEncapsulationAlgorithm;
        this.LibVersion = libVersion;
        Value = value;
    }
}
