namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationKeyPair : IKeyEncapsulationKeyPair
{
    public required KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; init; }
    public required IKeyEncapsulationPrivateKey PrivateKey { get; init; }
    public required IKeyEncapsulationPublicKey PublicKey { get; init; }
}
