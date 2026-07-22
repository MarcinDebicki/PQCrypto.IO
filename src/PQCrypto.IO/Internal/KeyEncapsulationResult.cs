namespace PQCrypto.IO.Internal;

public sealed record class KeyEncapsulationResult : IKeyEncapsulationResult
{
    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; init; }
    public required IKeyEncapsulationCiphertext KeyEncapsulationCiphertext { get; set; }
    public required IKeyEncapsulationSharedSecret KeyEncapsulationSharedSecret { get; set; }
    public required LibVersion LibVersion { get; init; }

    public void Dispose()
    {
        this.KeyEncapsulationCiphertext.Value = null;
        this.KeyEncapsulationSharedSecret.Value.Dispose();
    }
}
