using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Encryption
{
    public static class Encryption
    {
        private static readonly byte[] Salt = (ConfigurationManager.AppSettings["Salt"] == null ? "ADB928C878FC4D54844926688EBBE1C0".CreateMd5Hash() : ConfigurationManager.AppSettings["Salt"].CreateMd5Hash());

        /// <summary>
        /// Create a hashed password salted with a user unique identifier
        /// </summary>
        /// <param name="password">Clear text password to hash</param>
        /// <param name="userUniqueIdentifier">User unique identifier</param>
        /// <returns>Bytes of hashed password</returns>
        public static byte[] CreateMd5PasswordHash(this string password, string userUniqueIdentifier)
        {
            using (var md5Hash = MD5.Create())
                return md5Hash.ComputeHash(Encoding.UTF8.GetBytes(userUniqueIdentifier + password));
        }

        /// <summary>
        /// Create an MD5 hash of a password
        /// </summary>
        /// <param name="password">Clear text password to hash</param>
        /// <returns>Bytes of hashed password</returns>
        public static byte[] CreateMd5Hash(this string password)
        {
            using (var md5Hash = MD5.Create())
                return md5Hash.ComputeHash(Encoding.UTF8.GetBytes(password));
        }

        /// <summary>
        /// Encrypt data for a URL
        /// </summary>
        /// <param name="id">URL data to encrypt</param>
        /// <returns>Encrypted string of URL data</returns>
        public static string EncryptUrl(this string id)
        {
            return HttpUtility.UrlEncode(Encrypt(id, "URLEncrypt"));
        }

        /// <summary>
        /// Decrypt data for a URL
        /// </summary>
        /// <param name="id">URL data to decrypt</param>
        /// <returns>Decrypted string of URL data</returns>
        public static string DecryptUrl(this string id)
        {
            return HttpUtility.UrlDecode(Decrypt(id, "URLEncrypt"));
        }

        /// <summary>
        /// Encrypt string data with a password
        /// </summary>
        /// <param name="clearText">Data to encrypt</param>
        /// <param name="password">Password to encrypt with</param>
        /// <returns>Encrypted string</returns>
        public static string Encrypt(this string clearText, string password)
        {
            var bytes = Encoding.Unicode.GetBytes(clearText);
            var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, Salt);
            return
                Convert.ToBase64String(Encrypt(bytes, rfc2898DeriveBytes.GetBytes(32), rfc2898DeriveBytes.GetBytes(32)));
        }

        /// <summary>
        /// Decrypt string data with a password
        /// </summary>
        /// <param name="cipherText">Encrypted string data</param>
        /// <param name="password">Password to decrypt with</param>
        /// <returns>Decrypted string</returns>
        public static string Decrypt(this string cipherText, string password)
        {
            var cipherData = Convert.FromBase64String(cipherText);
            var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, Salt);
            return
                Encoding.Unicode.GetString(Decrypt(cipherData, rfc2898DeriveBytes.GetBytes(32),
                    rfc2898DeriveBytes.GetBytes(32)));
        }

        private static byte[] Decrypt(byte[] cipherData, byte[] key, byte[] iv)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var rijndael = Rijndael.Create())
                {
                    rijndael.KeySize = 256;
                    rijndael.BlockSize = 256;
                    rijndael.Key = key;
                    rijndael.IV = iv;
                    rijndael.Mode = CipherMode.CBC;
                    rijndael.Padding = PaddingMode.PKCS7;
                    using (
                        var cryptoStream = new CryptoStream(memoryStream, rijndael.CreateDecryptor(),
                            CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(cipherData, 0, cipherData.Length);
                        cryptoStream.Close();
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        private static byte[] Encrypt(byte[] clearData, byte[] key, byte[] iv)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var rijndael = Rijndael.Create())
                {
                    rijndael.KeySize = 256;
                    rijndael.BlockSize = 256;
                    rijndael.Key = key;
                    rijndael.IV = iv;
                    rijndael.Mode = CipherMode.CBC;
                    rijndael.Padding = PaddingMode.PKCS7;
                    using (
                        var cryptoStream = new CryptoStream(memoryStream, rijndael.CreateEncryptor(),
                            CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(clearData, 0, clearData.Length);
                        cryptoStream.Close();
                    }
                    return memoryStream.ToArray();
                }
            }
        }
    }
}
