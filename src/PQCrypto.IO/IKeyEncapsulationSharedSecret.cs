namespace PQCrypto.IO;

public interface IKeyEncapsulationSharedSecret
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    LibVersion LibVersion { get; }
    MemorySafe Value { get; }
}
