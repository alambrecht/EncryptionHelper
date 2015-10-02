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

        public static byte[] CreateMd5PasswordHash(this string password, string userUniqueIdentifier)
        {
            using (var md5Hash = MD5.Create())
                return md5Hash.ComputeHash(Encoding.UTF8.GetBytes(userUniqueIdentifier + password));
        }

        public static byte[] CreateMd5Hash(this string password)
        {
            using (var md5Hash = MD5.Create())
                return md5Hash.ComputeHash(Encoding.UTF8.GetBytes(password));
        }

        public static string EncryptUrl(this string id)
        {
            return HttpUtility.UrlEncode(Encrypt(id, "URLEncrypt"));
        }

        public static string DecryptUrl(this string id)
        {
            return HttpUtility.UrlDecode(Decrypt(id, "URLEncrypt"));
        }

        public static string Encrypt(this string clearText, string password)
        {
            var bytes = Encoding.Unicode.GetBytes(clearText);
            var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, Salt);
            return
                Convert.ToBase64String(Encrypt(bytes, rfc2898DeriveBytes.GetBytes(32), rfc2898DeriveBytes.GetBytes(32)));
        }

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
