namespace PQCrypto.IO;

public interface IKeyEncapsulationPrivateKey
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    LibVersion LibVersion { get; }
    byte[] Value { get; }
}
