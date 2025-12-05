namespace PQCrypto.IO.Internal;

public sealed record class Message : IMessage
{
    public byte[] Value { get; }

    public Message(byte[] value)
    {
        this.Value = value;
    }
}
