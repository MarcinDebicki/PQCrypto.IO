namespace PQCrypto.IO;

public interface IKeyEncapsulationSharedSecret
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    byte[] Value { get; }
}
