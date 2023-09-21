using System;
using dotnetstandard_bip32;
using System.Security.Cryptography;
using System.Text;

namespace MyConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            BIP32 bip32 = new BIP32();
            string seed = "23cd8f21118749c3d348e114a53b1cede7fd020bfa5f9bf67938b12d67b522aaf370480ed670a1c41aae0c0062faceb6aea0c031cc2907e8aaadd23ae8076818";
            /*string keyModifier = "Bitcoin seed";  // Or whatever you use as key modifier
            // print seed
            Console.WriteLine($"Seed: {seed}");
            // Debug prints before HMAC-SHA512 Hash
            Console.WriteLine($"C# - Key Modifier before HMAC-SHA512: {keyModifier}");
            Console.WriteLine($"C# - Seed before HMAC-SHA512: {seed}");
            // HMAC-SHA512 calculation
            using (HMACSHA512 hmac = new HMACSHA512(Encoding.UTF8.GetBytes(keyModifier)))
            {
                byte[] hmacSha512Hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(seed));

                // Debug prints after HMAC-SHA512 Hash
                Console.WriteLine($"C# - HMAC-SHA512 Hash: {BitConverter.ToString(hmacSha512Hash).Replace("-", "")}");
            }
            
            Console.WriteLine(">> C# - Key Modifier before HMAC: " + keyModifier);
            Console.WriteLine(">> C# - Seed before HMAC: " + seed);
            // Perform HMAC-SHA512 here
            // For example: byte[] hashResult = new HMACSHA512(keyModifier).ComputeHash(seed);
            byte[] hashResult = new HMACSHA512(Encoding.UTF8.GetBytes(keyModifier)).ComputeHash(Encoding.UTF8.GetBytes(seed));
            Console.WriteLine(">> C# - HMAC-SHA512 Hash: " + BitConverter.ToString(hashResult).Replace("-", ""));
            */

            var masterKeyFromSeed = bip32.GetMasterKeyFromSeed(seed);
            var publicKey = bip32.GetPublicKey(masterKeyFromSeed.Key);
            // Convert byte arrays to hex strings for easier viewing
            string privatekeyHex = BitConverter.ToString(masterKeyFromSeed.Key).Replace("-", "");
            string publicKeyHex = BitConverter.ToString(publicKey).Replace("-", "");
            string chainCodeHex = BitConverter.ToString(masterKeyFromSeed.ChainCode).Replace("-", "");            
            Console.WriteLine($"Chain Code: {chainCodeHex}");
            Console.WriteLine($"Private Key: {privatekeyHex}");
            Console.WriteLine($"Public Key: {publicKeyHex}");

            // Define the indexes
            /*uint index44 = 0x8000002c; // Or 2147483692 in decimal
            uint index9000 = 0x80002328; // Or 2147488816 in decimal
            uint index0Hardened = 0x80000000; // Or 2147483648 in decimal
            uint index0 = 0x00000000; // Or 0 in decimal*/

            // Derive the keys
            //var result1 = bip32.GetChildKeyDerivation(masterKeyFromSeed.Key, masterKeyFromSeed.ChainCode, index44);

            // Derive the key using the path "m/44'/9000'/0'/0/0"
            //const string expectedPath = "m/44'";
            //const string expectedPath = "m/44'/9000'";
            //const string expectedPath = "m/44'/9000'/0'"; // OK
            //const string expectedPath = "m/44'/9000'/0'/0'";
            //const string expectedPath = "m/44'/9000'/0'/0'/0'"; //2147483692
            //const string expectedPath = "m/44'/9000'/0'/0/0";
            const string expectedPath = "m/44'/9000'/0'/0";
            
            //var expectedPath = "m/44'";
            Console.WriteLine($"Path: {expectedPath}");
            var derivedKey = bip32.DerivePath(expectedPath, seed);
            publicKey = bip32.GetPublicKey(derivedKey.Key);            
            
            // Convert byte arrays to hex strings for easier viewing
            privatekeyHex = BitConverter.ToString(derivedKey.Key).Replace("-", "");
            publicKeyHex = BitConverter.ToString(publicKey).Replace("-", "");
            chainCodeHex = BitConverter.ToString(derivedKey.ChainCode).Replace("-", "");
            Console.WriteLine($"Derived Chain Code: {chainCodeHex}");
            Console.WriteLine($"Derived Private Key: {privatekeyHex}");
            Console.WriteLine($"Derived Public Key: {publicKeyHex}");
        }
    }
}
