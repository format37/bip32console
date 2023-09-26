using System;
using dotnetstandard_bip32;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests; // For RIPEMD160
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

public class Bech32Encoder
{
    private const string CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private const int CHECKSUM_LENGTH = 6;

    public static List<int> ConvertBytesTo5BitGroups(byte[] data)
    {
        List<int> result = new List<int>();
        int buffer = 0;
        int bufferLength = 0;

        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bufferLength += 8;

            while (bufferLength >= 5)
            {
                result.Add((buffer >> (bufferLength - 5)) & 31);
                bufferLength -= 5;
            }
        }

        // Add any remaining bits
        if (bufferLength > 0)
        {
            result.Add((buffer << (5 - bufferLength)) & 31);
        }
        // Inside ConvertBytesTo5BitGroups method
        Console.WriteLine("C# 5-bit groups: " + string.Join(", ", result));

        return result;
    }

    public static string Encode(string hrp, byte[] data)
    {
        List<int> values = ConvertBytesTo5BitGroups(data);
        int[] checksum = CreateChecksum(hrp, values.ToArray());
        values.AddRange(checksum);

        // Debugging: Print out the values
        Console.WriteLine("Values:");
        foreach (var val in values)
        {
            Console.WriteLine(val);
            if (val < 0 || val >= CHARSET.Length)
            {
                Console.WriteLine($"Value out of bounds: {val}");
                return null;  // or throw an exception
            }
        }

        return hrp + "1" + values.Select(x => CHARSET[x]).Aggregate("", (acc, c) => acc + c);
    }


    private static int[] CreateChecksum(string hrp, int[] data)
    {
        int[] values = ExpandHrp(hrp).Concat(data).Concat(new int[CHECKSUM_LENGTH]).ToArray();
        int polyMod = PolyMod(values) ^ 1;
        int[] checksum = new int[CHECKSUM_LENGTH];

        // Debugging: Print out the PolyMod and values
        Console.WriteLine($"PolyMod: {polyMod}");
        Console.WriteLine("Values in CreateChecksum:");
        foreach (var val in values)
        {
            Console.WriteLine(val);
        }

        for (int i = 0; i < CHECKSUM_LENGTH; ++i)
        {
            checksum[i] = (polyMod >> 5 * (5 - i)) & 31;
        }
        return checksum;
    }

    private static int PolyMod(int[] values)
    {
        BigInteger chk = 1;
        int[] generator = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
        foreach (int v in values)
        {
            int top = (int)(chk >> 25);
            Console.WriteLine($"\nC# pre-Intermediate chk: {chk}, top: {top}");
            chk = (chk & 0x1ffffff) << 5 ^ v;
            Console.WriteLine($"C# >>>>Intermediate chk: {chk}");          
            for (int i = 0; i < 5; ++i)
            {
                chk ^= ((top >> i) & 1) == 1 ? generator[i] : 0;
            }
        }
        Console.WriteLine("C# PolyMod: " + chk);
        return (int)chk;
    }

    private static int[] ExpandHrp(string hrp)
    {
        int[] ret = new int[hrp.Length * 2 + 1];
        for (int i = 0; i < hrp.Length; ++i)
        {
            int c = hrp[i];
            ret[i] = c >> 5;
            ret[i + hrp.Length + 1] = c & 31;
        }
        ret[hrp.Length] = 0;
        return ret;
    }
}

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
            string b32Encoded = Bech32Encoder.Encode("avax", ripemd160Hash); // TODO: Implement Bech32Encoder

            // Return final address
            return "P-" + b32Encoded;
            //return "P-" + BitConverter.ToString(ripemd160Hash).Replace("-", "");
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

            // Derive a child key
            Console.WriteLine("\nDerive a child key");
            var derivedKey = bip32.DerivePath(seed);
            Console.WriteLine($"...");
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
            Console.WriteLine($"\navaxp: {avaxpAddress}");
        }
    }
}
