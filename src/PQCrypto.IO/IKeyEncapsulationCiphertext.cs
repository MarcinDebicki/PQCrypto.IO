namespace PQCrypto.IO;

public interface IKeyEncapsulationCiphertext
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    LibVersion LibVersion { get; }
    byte[] Value { get; }
}
