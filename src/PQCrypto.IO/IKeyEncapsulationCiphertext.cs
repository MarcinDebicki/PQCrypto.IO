namespace PQCrypto.IO;

public interface IKeyEncapsulationCiphertext
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    byte[] Value { get; }
}
