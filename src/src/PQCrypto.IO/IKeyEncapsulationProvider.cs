namespace PQCrypto.IO;

public interface IKeyEncapsulationProvider
{
    KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; }
    IKeyEncapsulationResult Decapsulation(in IKeyEncapsulationCiphertext keyEncapsulationCiphertext, in IKeyEncapsulationPrivateKey keyEncapsulationPrivateKey);
    IKeyEncapsulationResult Encapsulation(in IKeyEncapsulationPublicKey publicKey);
    IKeyEncapsulationKeyPair GenerateKeyPair();
}
