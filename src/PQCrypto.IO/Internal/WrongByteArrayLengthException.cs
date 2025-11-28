namespace PQCrypto.IO.Internal;

using System.Security.Cryptography;

/// <summary>
///     Thrown when a byte array passed to a cryptographic operation has incorrect length.
/// </summary>
public sealed class WrongByteArrayLengthException : CryptographicException
{
    /// <summary>
    ///     Gets the actual length of the provided array (if known).
    /// </summary>
    public int? ActualLength { get; }

    /// <summary>
    ///     Gets the expected length in bytes.
    /// </summary>
    public int ExpectedLength { get; }
    /// <summary>
    ///     Gets the name of the field/parameter that had wrong length.
    /// </summary>
    public string Field { get; }

    public WrongByteArrayLengthException(string field, int expectedLength)
        : this(field, expectedLength, actualLength: null, innerException: null)
    {
    }

    public WrongByteArrayLengthException(string field, int expectedLength, int actualLength)
        : this(field, expectedLength, actualLength, innerException: null)
    {
    }

    public WrongByteArrayLengthException(string field, int expectedLength, Exception? innerException)
        : this(field, expectedLength, actualLength: null, innerException)
    {
    }

    private WrongByteArrayLengthException(string field, int expectedLength, int? actualLength, Exception? innerException)
        : base(BuildMessage(field, expectedLength, actualLength), innerException)
    {
        this.Field = field;
        this.ExpectedLength = expectedLength;
        this.ActualLength = actualLength;
    }

    private static string BuildMessage(string field, int expected, int? actual)
    {
        return actual.HasValue
            ? $"The byte array for '{field}' has incorrect length. Expected: {expected} bytes, but was: {actual.Value} bytes."
            : $"The byte array for '{field}' must be exactly {expected} bytes long.";
    }
}
