namespace PQCrypto.IO;

public interface IKeyEncapsulationPublicKey
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    byte[] Value { get; }
}
