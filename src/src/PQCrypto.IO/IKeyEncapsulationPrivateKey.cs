namespace PQCrypto.IO;

public interface IKeyEncapsulationPrivateKey
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    byte[] Value { get; }
}
