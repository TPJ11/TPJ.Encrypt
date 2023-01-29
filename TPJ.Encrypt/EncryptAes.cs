using System.Security.Cryptography;

namespace TPJ.Encrypt;

public static class EncryptAes
{
    /// <summary>
    /// Creates a base 64 strings for a key and IV
    /// </summary>
    /// <returns>Key and IV in base 64 string</returns>
    public static (string key, string iv) GenerateBase64StringKeyIV()
    {
        var (key, iv) = GenerateByteKeyIV();

        return (Convert.ToBase64String(key), Convert.ToBase64String(iv));
    }

    /// <summary>
    /// Creates a key and IV
    /// </summary>
    /// <returns>Key and IV bytes</returns>
    public static (byte[] key, byte[] iv) GenerateByteKeyIV()
    {
        using Aes myAes = Aes.Create();

        return (myAes.Key, myAes.IV);
    }

    /// <summary>
    /// Encrypt the given value creating a new key and iv
    /// </summary>
    /// <param name="plainText">Value to encrypt</param>
    /// <returns>Encrypted value in base 64 string along with the key and iv also in base 64 string</returns>
    public static (string? cipherText, string key, string iv) EncryptToBase64String(string plainText)
    {
        var (keyBytes, ivBytes) = GenerateByteKeyIV();
        return (EncryptToBase64String(plainText, keyBytes, ivBytes), Convert.ToBase64String(keyBytes), Convert.ToBase64String(ivBytes));
    }

    /// <summary>
    /// Encrypt the given value creating a new key and iv
    /// </summary>
    /// <param name="plainText">Value to encrypt</param>
    /// <returns>Encrypted value bytes along with the key and iv also in bytes</returns>
    public static (byte[]? cipherText, byte[] key, byte[] iv) EncryptToBytes(string plainText)
    {
        var (keyBytes, ivBytes) = GenerateByteKeyIV();
        return (EncryptToBytes(plainText, keyBytes, ivBytes), keyBytes, ivBytes);
    }

    /// <summary>
    /// Encrypt the given value using the given key and IV
    /// </summary>
    /// <param name="plainText">Value to encrypt</param>
    /// <param name="key">Encrypt key</param>
    /// <param name="iv">Encrypt IV</param>
    /// <returns>Encrypted value in base 64 string</returns>
    public static string? EncryptToBase64String(string plainText, string key, string iv)
    {
        var keyBytes = Convert.FromBase64String(key);
        var ivBytes = Convert.FromBase64String(iv);

        return EncryptToBase64String(plainText, keyBytes, ivBytes);
    }

    /// <summary>
    /// Encrypt the given value using the given key and IV
    /// </summary>
    /// <param name="plainText">Value to encrypt</param>
    /// <param name="key">Encrypt key</param>
    /// <param name="iv">Encrypt IV</param>
    /// <returns>Encrypted value in base 64 string</returns>
    public static string? EncryptToBase64String(string plainText, byte[] key, byte[] iv)
    {
        var encryptedBytes = EncryptToBytes(plainText, key, iv);

        return encryptedBytes is not null ? Convert.ToBase64String(encryptedBytes) : null;
    }

    /// <summary>
    /// Encrypt the given value using the given key and IV
    /// </summary>
    /// <param name="plainText">Value to encrypt</param>
    /// <param name="key">Encrypt key</param>
    /// <param name="iv">Encrypt IV</param>
    /// <returns>Encrypted value bytes</returns>
    public static byte[]? EncryptToBytes(string plainText, string key, string iv)
    {
        var keyBytes = Convert.FromBase64String(key);
        var ivBytes = Convert.FromBase64String(iv);

        return EncryptToBytes(plainText, keyBytes, ivBytes);
    }

    /// <summary>
    /// Encrypt the given value using the given key and IV
    /// </summary>
    /// <param name="plainText">Value to encrypt</param>
    /// <param name="key">Encrypt key</param>
    /// <param name="iv">Encrypt IV</param>
    /// <returns>Encrypted value bytes</returns>
    public static byte[]? EncryptToBytes(string plainText, byte[] key, byte[] iv)
    {
        // Check arguments.
        if (plainText == null || plainText.Length <= 0)
            return null;
        if (key == null || key.Length <= 0)
            throw new ArgumentNullException(nameof(key));
        if (iv == null || iv.Length <= 0)
            throw new ArgumentNullException(nameof(iv));

        byte[] encrypted;

        // Create an Aes object
        // with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            // Create an encryptor to perform the stream transform.
            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                //Write all data to the stream.
                swEncrypt.Write(plainText);
            }

            encrypted = msEncrypt.ToArray();
        }

        // Return the encrypted bytes from the memory stream.
        return encrypted;
    }

    /// <summary>
    /// Decrypt the given cipher value with the given key and IV
    /// </summary>
    /// <param name="cipherText">Encrypted value</param>
    /// <param name="key">Encrypt key</param>
    /// <param name="iv">Encrypt IV</param>
    /// <returns>Unencrypted value</returns>
    public static string? Decrypt(string cipherText, string key, string iv)
    {
        var keyBytes = Convert.FromBase64String(key);
        var ivBytes = Convert.FromBase64String(iv);

        return Decrypt(cipherText, keyBytes, ivBytes);
    }

    /// <summary>
    /// Decrypt the given cipher value with the given key and IV
    /// </summary>
    /// <param name="cipherText">Encrypted value</param>
    /// <param name="key">Encrypt key</param>
    /// <param name="iv">Encrypt IV</param>
    /// <returns>Unencrypted value</returns>
    public static string? Decrypt(string cipherText, byte[] key, byte[] iv) 
        => Decrypt(Convert.FromBase64String(cipherText), key, iv);

    /// <summary>
    /// Decrypt the given cipher value with the given key and IV
    /// </summary>
    /// <param name="cipherText">Encrypted value</param>
    /// <param name="key">Encrypt key</param>
    /// <param name="iv">Encrypt IV</param>
    /// <returns>Unencrypted value</returns>
    public static string? Decrypt(byte[] cipherText, byte[] key, byte[] iv)
    {
        // Check arguments.
        if (cipherText == null || cipherText.Length <= 0)
            return null;
        if (key == null || key.Length <= 0)
            throw new ArgumentNullException(nameof(key));
        if (iv == null || iv.Length <= 0)
            throw new ArgumentNullException(nameof(iv));

        // Declare the string used to hold
        // the decrypted text.
        string? plaintext = null;

        // Create an Aes object
        // with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            // Create a decryptor to perform the stream transform.
            var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption.
            using var msDecrypt = new MemoryStream(cipherText);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);

            // Read the decrypted bytes from the decrypting stream
            // and place them in a string.
            plaintext = srDecrypt.ReadToEnd();
        }

        return plaintext;
    }
}
