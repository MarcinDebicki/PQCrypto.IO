namespace PQCrypto.IO;

public interface IKeyEncapsulationPrivateKey : IDisposable
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    LibVersion LibVersion { get; }
    MemorySafe Value { get; }
}
