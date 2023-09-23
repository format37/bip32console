using System;
using dotnetstandard_bip32;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests; // For RIPEMD160
//using Bech32EncoderLib;

namespace MyConsoleApp
{
    class Program
    {
        public static byte[] HexToByteArray(string hex)
        {
            byte[] byteArray = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                byteArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return byteArray;
        }

        // Print the byte array in a readable format.
        public static void PrintByteArray(byte[] array)
        {
            for (int i = 0; i < array.Length; i++)
            {
                Console.Write(String.Format("{0:X2}", array[i]));
                if ((i % 4) == 3) Console.Write(" ");
            }
            Console.WriteLine();
        }

        public static byte[] ComputeRipemd160(byte[] data)
        {
            var digest = new RipeMD160Digest();
            var output = new byte[digest.GetDigestSize()];

            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(output, 0);

            return output;
        }

        public static string ChildToAvaxpAddress(string publicKeyHex)
        {
            // Convert hex to byte array
            byte[] publicKeyBytes = HexStringToByteArray(publicKeyHex);

            // SHA-256 Hashing
            byte[] sha256Hash;
            using (SHA256 sha256 = SHA256.Create())
            {
                sha256Hash = sha256.ComputeHash(publicKeyBytes);
            }

            // RIPEMD-160 Hashing using BouncyCastle
            byte[] ripemd160Hash = ComputeRipemd160(sha256Hash);

            // Bech32 Encoding (assuming you have a Bech32Encoder class)
            //string b32Encoded = Bech32Encoder.Encode("avax", ripemd160Hash); // TODO: Implement Bech32Encoder

            // Return final address
            //return "P-" + b32Encoded;
            return "P-" + BitConverter.ToString(ripemd160Hash).Replace("-", "");
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        static void Main(string[] args)
        {
            BIP32 bip32 = new BIP32();
            string seed = "23cd8f21118749c3d348e114a53b1cede7fd020bfa5f9bf67938b12d67b522aaf370480ed670a1c41aae0c0062faceb6aea0c031cc2907e8aaadd23ae8076818";
            Console.WriteLine($"Seed: {seed}");

            var masterKeyFromSeed = bip32.GetMasterKeyFromSeed(seed);
            var publicKey = bip32.GetPublicKey(masterKeyFromSeed.Key);
            // Convert byte arrays to hex strings for easier viewing
            string privatekeyHex = BitConverter.ToString(masterKeyFromSeed.Key).Replace("-", "");
            string publicKeyHex = BitConverter.ToString(publicKey).Replace("-", "");
            string chainCodeHex = BitConverter.ToString(masterKeyFromSeed.ChainCode).Replace("-", "");            
            Console.WriteLine($"Chain Code: {chainCodeHex}");
            Console.WriteLine($"Private Key: {privatekeyHex}");
            Console.WriteLine($"Public Key: {publicKeyHex}");

            var derivedKey = bip32.DerivePath(seed);
            publicKey = bip32.GetPublicKey(derivedKey.Key);            
            
            // Convert byte arrays to hex strings for easier viewing
            privatekeyHex = BitConverter.ToString(derivedKey.Key).Replace("-", "");
            publicKeyHex = BitConverter.ToString(publicKey).Replace("-", "");
            chainCodeHex = BitConverter.ToString(derivedKey.ChainCode).Replace("-", "");
            Console.WriteLine($"\nDerived Chain Code: {chainCodeHex}");
            Console.WriteLine($"Derived Private Key: {privatekeyHex}");
            Console.WriteLine($"Derived Public Key: {publicKeyHex}");

            // avax
            string avaxpAddress = ChildToAvaxpAddress(publicKeyHex);
            Console.WriteLine($"\nAvaxp Address: {avaxpAddress}");
        }
    }
}
