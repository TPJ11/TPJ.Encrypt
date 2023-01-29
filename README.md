# TPJ.Encrypt
Simple encrypt library for both one way encryption using SHA256 and two-way encryption using AES 

# One Way Encrypt
One way encrypt is used for values where you never need to know what the 'real' value is again but you need to compare to see if a given value is the same as the encrypted value such as comparing passwords when logging a user in.

This library uses SHA256 to encrypt a string value, you can set the salt size and the iterations used to encrypt this value the defaults are for a 128bit salt key using 200,000 iterations which is strong encryption the iterations can be reduced to improve performance.

## Password example
As the normal use of this is for passwords let's do an example for it.

Your user will sign up to your app passing in the user details such as name and email but also their password (you may also with to encrypt the name and email which you can do using the AES encryption). 

Taking the password, you want to encrypt it and save the result of the encryption to your database this is done by calling `OneWayEncrypt.EncryptToBytes(password)` the result is the cipher of the password and the salt used to encrypt it. You should save both the cipher (which is the password) and the salt to the user object, the salt is important as this makes the encryption unique to that cipher so even if another user has the same password the cipher result will be different when using a different salt meaning even if a brute force attack was successful on one user password they would have to brute force attack again for all the other users.

```
var (passwordCipherText, passwordSalt) = OneWayEncrypt.EncryptToBytes(password);

var user = new User() 
{
    Password = passwordCipherText,
    Salt = passwordSalt,
    ...
}
```

Now when your user comes to login they will normally give you their email and password. You can get the user based off the email then use the password they have submitted and the salt from the user account found matching the given email to check to see if the password value they have submitted matches the stored password.

```
var user = _context.User.FindByEmail(email);

if(!user.Password.Equals(OneWayEncrypt.EncryptToBytes(password, user.Salt)))
   throw new Exception();
```

I have used the byte version of the methods for encrypt but you can also use the base64 version which returns base 64 strings instead of bytes which you might find easier to store in your database. You should at least add lock out login on failed attempts to stop brute force attacks via your login page.

# Two-Way Encrypt
When you have a value that you want to encrypt but you want to be able to unencrypt at some point to read the 'real' value you'll need to do two-way encryption, this is often used for emails. If you are just doing this to store the value at rest often the database you are using can already encrypt values at rest and its a lot easier to use that but if you and transmitting a value you may want to encrypt it.

The important part of two-way encryption is understanding that the encrpytion is designed to be unencrypted so by its very nature its only as secure as how you store the keys to unencrypt it. In AES there are two 'keys' the key itself and the IV (initialization vector) you need both to unencrypt the value therefore you may wish to store both the values in different places to make it harder to attack.

To encrypt a value where you want it to create a new pair of key IV simply call 
```
var (cipherText, key, iv) = EncryptAes.EncryptToBytes(value);
```
or 

```
var (cipherText, key, iv) = EncryptAes.EncryptToBase64String(value);
```

As with one way the bytes return byte version of the encrypted value, key, and IV. whereas the base 64 string return string values.

You can then use those returned values to decrypt.
```
var value = EncryptAes.Decrypt(cipherText, key, iv);
```

Normally you will already have the key and IV created and you are using that to encrypt a new value in which case you simply pass in the value you wish to encrypt and the key IV

```
var cipherText = EncryptAes.EncryptToBytes(value, key, iv)
```