namespace PQCrypto.IO;

public interface IKeyEncapsulationResult
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    IKeyEncapsulationCiphertext KeyEncapsulationCiphertext { get; }
    IKeyEncapsulationSharedSecret KeyEncapsulationSharedSecret { get; }
}
