using System.Security.Cryptography;

namespace TPJ.Encrypt;

public static class OneWayEncrypt
{
    /// <summary>
    /// Encrypt the given string text using the given string salt using SHA256 with the number of iterations
    /// </summary>
    /// <param name="plainText">Text to encrypt</param>
    /// <param name="salt">Salt to encrypt with</param>
    /// <param name="saltSize">Salt size that the salt value was when it was created to encrypt normally 16 or 32</param>
    /// <param name="iterations">Number of iterations</param>
    /// <returns>Base 64 string of the cipher text value</returns>
    public static string EncryptToBase64String(string plainText, string salt, int saltSize = 16, int iterations = 200000) => 
        EncryptToBase64String(plainText, Convert.FromBase64String(salt), saltSize, iterations);

    /// <summary>
    /// Encrypt the given string text using the given string salt using SHA256 with the number of iterations
    /// </summary>
    /// <param name="plainText">Text to encrypt</param>
    /// <param name="salt">Salt to encrypt with</param>
    /// <param name="saltSize">Salt size that the salt value was when it was created to encrypt normally 16 or 32</param>
    /// <param name="iterations">Number of iterations</param>
    /// <returns>Base 64 string of the cipher text value</returns>
    public static string EncryptToBase64String(string plainText, byte[] salt, int saltSize = 16, int iterations = 200000)
    {
        var cipherText = EncryptToBytes(plainText, salt, saltSize, iterations);
        return Convert.ToBase64String(cipherText);
    }

    /// <summary>
    /// Encrypt the given string text using the given string salt using SHA256 with the number of iterations
    /// </summary>
    /// <param name="plainText">Text to encrypt</param>
    /// <param name="salt">Salt to encrypt with</param>
    /// <param name="saltSize">Salt size that the salt value was when it was created to encrypt normally 16 or 32</param>
    /// <param name="iterations">Number of iterations</param>
    /// <returns>Cipher text value</returns>
    public static byte[] EncryptToBytes(string plainText, string salt, int saltSize = 16, int iterations = 200000)
        => EncryptToBytes(plainText, Convert.FromBase64String(salt), saltSize, iterations);

    /// <summary>
    /// Encrypt the given string text using the given salt using SHA256 with the number of iterations
    /// </summary>
    /// <param name="plainText">Text to encrypt</param>
    /// <param name="salt">Salt to encrypt with</param>
    /// <param name="saltSize">Salt size that the salt value was when it was created to encrypt normally 16 or 32</param>
    /// <param name="iterations">Number of iterations</param>
    /// <returns>Cipher text value</returns>
    public static byte[] EncryptToBytes(string plainText, byte[] salt, int saltSize = 16, int iterations = 200000)
    {
        using var derivedBytes = new Rfc2898DeriveBytes(plainText, salt, iterations: iterations, HashAlgorithmName.SHA256);
        return derivedBytes.GetBytes(saltSize);
    }

    /// <summary>
    /// Encrypt the given string text creating a salt at the given size 
    /// (default is 16 which equals a 128 bit key) using SHA256 with the number of iterations
    /// </summary>
    /// <param name="plainText">Text to encrypt</param>
    /// <param name="saltSize">Salt size to encrypt with 16 or 32 is suggested</param>
    /// <param name="iterations">Number of iterations</param>
    /// <returns>Base 64 string of the 8 x saltSize bit key of the encrypted value along with the salt key value also in base 64 string</returns>
    public static (string cipherText, string salt) EncryptToBase64String(string plainText, int saltSize = 16, int iterations = 200000)
    {
        var (cipherText, salt) = EncryptToBytes(plainText, saltSize, iterations);
        return (Convert.ToBase64String(cipherText), Convert.ToBase64String(salt));
    }

    /// <summary>
    /// Encrypt the given string text creating a salt at the given size 
    /// (default is 16 which equals a 128 bit key) using SHA256 with the number of iterations
    /// </summary>
    /// <param name="plainText">Text to encrypt</param>
    /// <param name="saltSize">Salt size to encrypt with 16 or 32 is suggested</param>
    /// <param name="iterations">Number of iterations</param>
    /// <returns>8 x saltSize bit key of the encrypted value along with the salt key value</returns>
    public static (byte[] cipherText, byte[] salt) EncryptToBytes(string plainText, int saltSize = 16, int iterations = 200000)
    {
        byte[] salt;
        using var derivedBytes = new Rfc2898DeriveBytes(plainText, saltSize: saltSize, iterations: iterations, HashAlgorithmName.SHA256);
        salt = derivedBytes.Salt;
        byte[] key = derivedBytes.GetBytes(saltSize); // 8 x saltSize e.g. 16 x 8 = 128 bits key
        return (key, salt);
    }
}
