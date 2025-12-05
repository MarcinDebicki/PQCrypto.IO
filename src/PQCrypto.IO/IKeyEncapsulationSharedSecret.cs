namespace PQCrypto.IO;

public interface IKeyEncapsulationSharedSecret
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    LibVersion LibVersion { get; }

    byte[] Value { get; }
}
