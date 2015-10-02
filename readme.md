# Encryption Helper

A group of methods to assist with encryption

Add the folowing line to the App.config or web.config app settings for the salt

```
&lt;add key=&quot;Salt&quot; value=&quot;SALT VALUE HERE&quot; /&gt;
```

Usage:

### Create and MD5 hash salted with the user unique identifier and salt
```
var bytesOfHash = "Password".CreateMd5PasswordHash(userUniqueIdentifier);
```

### Create a salted MD5 hash of a password
```
var bytesOfHash = "Password".CreateMd5Hash();
```

### Encrypt URL data and URL Encode it
```
var encryptedString = "url data".EncryptUrl();
```

### Decrypt URL data and URL Deccode it
```
var decryptedString = "encrypted data".DecryptUrl();
```

### Encrypt data with a password
```
var bytesOfEncryptedData = "Decrypted data".Encrypt("password");
```

### Decrypt data with a password
```
var bytesOfDecryptedData = "Encrypted data".Decrypt("password");
```