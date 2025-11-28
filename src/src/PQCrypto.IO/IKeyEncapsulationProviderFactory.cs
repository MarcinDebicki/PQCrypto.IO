namespace PQCrypto.IO;

public interface IKeyEncapsulationProviderFactory
{
    IKeyEncapsulationProvider Create(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm);
}
