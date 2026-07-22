namespace PQCrypto.IO;

public interface IKeyEncapsulationPublicKey : IDisposable
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    LibVersion LibVersion { get; }
    byte[] Value { get; }
}
