namespace PQCrypto.IO;

public interface IKeyEncapsulationPublicKey
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    LibVersion LibVersion { get; }
    byte[] Value { get; }
}
