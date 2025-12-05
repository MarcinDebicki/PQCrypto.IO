namespace PQCrypto.IO;

public interface IKeyEncapsulationProviderFactory
{
    IKeyEncapsulationProvider Create(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm, LibVersion version = LibVersion.libopq_0_15_0_1);
}
