namespace PQCrypto.IO;

public interface IKeyEncapsulationResult : IDisposable
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    IKeyEncapsulationCiphertext KeyEncapsulationCiphertext { get; }
    IKeyEncapsulationSharedSecret KeyEncapsulationSharedSecret { get; }
    LibVersion LibVersion { get; }
}
