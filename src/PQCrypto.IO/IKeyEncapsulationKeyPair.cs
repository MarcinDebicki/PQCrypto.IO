namespace PQCrypto.IO;

public interface IKeyEncapsulationKeyPair
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; init; }
    IKeyEncapsulationPrivateKey PrivateKey { get; init; }
    IKeyEncapsulationPublicKey PublicKey { get; init; }
}
