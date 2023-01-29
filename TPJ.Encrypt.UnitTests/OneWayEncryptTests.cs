using FluentAssertions;

namespace TPJ.Encrypt.UnitTests;

public class OneWayEncryptTests
{
    [Test]
    public void EncryptToBytes_ShouldMatchPasswords()
    {
        var myPassword = "My3uperEp1cPa33w0rd";

        var (myPasswordCipherText, myPasswordSalt) = OneWayEncrypt.EncryptToBytes(myPassword);
        var myPasswordCipherText2 = OneWayEncrypt.EncryptToBytes(myPassword, myPasswordSalt);
        
        myPasswordCipherText2.Should().BeEquivalentTo(myPasswordCipherText);
    }

    [Test]
    public void EncryptToBytes_ShouldNotMatchPasswords()
    {
        var myPassword = "My3uperEp1cPa33w0rd";
        var notMyPassword = "NotMy3uperEp1cPa33w0rd";

        var (myPasswordCipherText, myPasswordSalt) = OneWayEncrypt.EncryptToBytes(myPassword);
        var notMyPasswordCipherText = OneWayEncrypt.EncryptToBytes(notMyPassword, myPasswordSalt);

        notMyPasswordCipherText.Should().NotBeEquivalentTo(myPasswordCipherText);
    }

    [Test]
    public void EncryptToBase64String_ShouldMatchPasswords()
    {
        var myPassword = "My3uperEp1cPa33w0rd";

        var (myPasswordCipherText, myPasswordSalt) = OneWayEncrypt.EncryptToBase64String(myPassword);
        var myPasswordCipherText2 = OneWayEncrypt.EncryptToBase64String(myPassword, myPasswordSalt);

        myPasswordCipherText2.Should().BeEquivalentTo(myPasswordCipherText);
    }

    [Test]
    public void EncryptToBase64String_ShouldNotMatchPasswords()
    {
        var myPassword = "My3uperEp1cPa33w0rd";
        var notMyPassword = "NotMy3uperEp1cPa33w0rd";

        var (myPasswordCipherText, myPasswordSalt) = OneWayEncrypt.EncryptToBase64String(myPassword);
        var notMyPasswordCipherText = OneWayEncrypt.EncryptToBase64String(notMyPassword, myPasswordSalt);

        notMyPasswordCipherText.Should().NotBeEquivalentTo(myPasswordCipherText);
    }
}