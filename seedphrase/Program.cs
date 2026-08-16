using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

internal class Program
{
    static void Main()
    {
        Console.WriteLine("BIP-39 24-word mnemonic generator");
        Console.WriteLine("==================================");
        Console.WriteLine();

        // ---------------------------------------------------------
        // Load BIP-39 English word list from current directory
        // ---------------------------------------------------------

        string[] words;

        string wordListPath = Path.Combine(AppContext.BaseDirectory, "BIP0039-wordlist-english.txt");
        string content = File.ReadAllText(wordListPath);

        words = content
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(x => x.Trim())
            .ToArray();

        if (words.Length != 2048)
        {
            throw new Exception($"ERROR: Invalid BIP-39 word list. Expected 2048 words, got {words.Length}");
        }

        // ----------------------------------------------------------------------
        // Generate 256 bits of cryptographically secure entropy
        // Calculate SHA-256 (used for checksum validation and the last 24th word
        // ----------------------------------------------------------------------

        byte[] entropy = new byte[32];

        RandomNumberGenerator.Fill(entropy);        // randomly fill the entropy array with 32 bytes (256 bits) of secure random data
        byte[] hash = SHA256.HashData(entropy);     // create checksum by hashing the entropy with SHA-256

        // Convert entropy (byte array) to bits
        StringBuilder bits = new StringBuilder(264);

        foreach (byte b in entropy)
        {
            bits.Append(Convert.ToString(b, 2).PadLeft(8, '0'));
        }

        // Append first 8 bits of SHA-256 as part of the 24th word
        // 256-bit entropy => 8-bit checksum
        int checksumBits = 8;

        string hashBits = Convert
            .ToString(hash[0], 2)
            .PadLeft(8, '0');

        bits.Append(hashBits.Substring(0, checksumBits));

        // expecting 24 words, which is 24 * 11 = 264 bits
        if (bits.Length != 264)
        {
            throw new Exception($"Eerror: expected 264 bits, got {bits.Length}");
        }

        // ---------------------------------------------------------
        // Convert 264 bits into 24 x 11-bit word indexes
        // ---------------------------------------------------------

        List<string> mnemonic = new List<string>();

        for (int i = 0; i < 24; i++)
        {
            string wordBits = bits
                .ToString()
                .Substring(i * 11, 11);

            int index = Convert.ToInt32(wordBits, 2);

            mnemonic.Add(words[index]);
        }

        // ---------------------------------------------------------
        // Display mnemonic
        // ---------------------------------------------------------

        Console.WriteLine("24-WORD BIP-39 MNEMONIC");
        Console.WriteLine("-----------------------");
        Console.WriteLine();

        for (int i = 0; i < mnemonic.Count; i++)
        {
            Console.WriteLine($"{i + 1,2}. {mnemonic[i]}");
        }

        Console.WriteLine();
        Console.WriteLine("Mnemonic:");
        Console.WriteLine();
        Console.WriteLine(string.Join(" ", mnemonic));

        Console.WriteLine();

        // Display entropy
        Console.WriteLine("Entropy:");
        Console.WriteLine(Convert.ToHexString(entropy));

        Console.WriteLine();

        // Verify mnemonic
        bool valid = ValidateMnemonic(mnemonic, words);

        Console.WriteLine( $"BIP-39 checksum: {(valid ? "VALID" : "INVALID")}");

        Console.WriteLine();

        if (!valid)
        {
            throw new Exception("Generated mnemonic failed validation!");
        }

        Console.WriteLine("\n\n");
        Console.WriteLine("#####################################################################");
        Console.WriteLine("DO NOT STORE SEED PHRASE ON THE COMPUTER OR SEND IT BY CHAT OR EMAIL");
        Console.WriteLine("#####################################################################");
    }


    // =============================================================
    // BIP-39 VALIDATION
    // =============================================================

    static bool ValidateMnemonic(
        List<string> mnemonic,
        string[] words)
    {
        if (mnemonic.Count != 24)
            return false;

        // Convert words back into 264 bits
        StringBuilder bits = new StringBuilder(264);

        foreach (string word in mnemonic)
        {
            int index = Array.IndexOf(words, word);

            if (index < 0)
                return false;

            bits.Append(
                Convert.ToString(index, 2).PadLeft(11, '0'));
        }

        if (bits.Length != 264)
            return false;

        // ---------------------------------------------------------
        // First 256 bits = entropy
        // Last 8 bits = checksum
        // ---------------------------------------------------------

        string entropyBits = bits.ToString(0, 256);
        string checksumBits = bits.ToString(256, 8);

        // Convert entropy bits back to bytes

        byte[] entropy = new byte[32];

        for (int i = 0; i < 32; i++)
        {
            string byteBits = entropyBits.Substring(i * 8, 8);

            entropy[i] = Convert.ToByte(byteBits, 2);
        }

        // Calculate SHA-256 of entropy

        byte[] hash = SHA256.HashData(entropy);

        string calculatedChecksum =
            Convert.ToString(hash[0], 2)
                .PadLeft(8, '0');

        // Compare checksum

        return calculatedChecksum == checksumBits;
    }
}