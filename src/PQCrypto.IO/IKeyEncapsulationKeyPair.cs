namespace PQCrypto.IO;

public interface IKeyEncapsulationKeyPair
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; init; }
    LibVersion LibVersion { get; }
    IKeyEncapsulationPrivateKey PrivateKey { get; init; }
    IKeyEncapsulationPublicKey PublicKey { get; init; }
}
