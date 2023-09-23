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
        }
    }
}
