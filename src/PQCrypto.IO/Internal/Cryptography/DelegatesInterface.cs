namespace PQCrypto.IO.Internal.Cryptography;

using System.Runtime.InteropServices;

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int GenerateKeypair(byte[] publicKey, byte[] secretKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int Decaps(byte[] plainSessionKey, byte[] secretSessionKey, byte[] privateKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int Encaps(byte[] secretSessionKey, byte[] plainSessionKey, byte[] publicKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int Sign(byte[] signature, ref nuint signatureLen, byte[] message, nuint messageLen, byte[] secretKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int Verify(byte[] message, nuint messageLen, byte[] signature, nuint signatureLen, byte[] publicKey);
