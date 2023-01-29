using FluentAssertions;

namespace TPJ.Encrypt.UnitTests;

public class EncryptAesTests
{
    [Test]
    public void EncryptToBytes_ShouldMatchCipherText_WhenUsingSameKeyIV()
    {
        var myEmail = "test@test.com";

        var (myEmailCipherText, key, iv) = EncryptAes.EncryptToBytes(myEmail);
        var myEmailCipherText2 = EncryptAes.EncryptToBytes(myEmail, key, iv);

        myEmailCipherText2.Should().BeEquivalentTo(myEmailCipherText);
    }

    [Test]
    public void EncryptToBytes_ShouldNotMatchCipherText_WhenUsingDifferentKeyIV()
    {
        var myEmail = "test@test.com";

        var (myEmailCipherText, key, iv) = EncryptAes.EncryptToBytes(myEmail);
        var (myEmailCipherText2, key2, iv2) = EncryptAes.EncryptToBytes(myEmail);

        myEmailCipherText2.Should().NotBeEquivalentTo(myEmailCipherText);
    }

    [Test]
    public void EncryptToBytes_ShouldDecryptCipherText()
    {
        var myEmail = "test@test.com";

        var (myEmailCipherText, key, iv) = EncryptAes.EncryptToBytes(myEmail);

        var decryptMyEmail = EncryptAes.Decrypt(myEmailCipherText, key, iv);

        decryptMyEmail.Should().BeEquivalentTo(myEmail);
    }

    [Test]
    public void EncryptToBytes_ShouldThrowException_WhenDecryptingUsingDifferentKeyIV()
    {
        var myEmail = "test@test.com";

        var (myEmailCipherText, key, iv) = EncryptAes.EncryptToBytes(myEmail);

        var (key2, iv2) = EncryptAes.GenerateByteKeyIV();

        Action act = () => EncryptAes.Decrypt(myEmailCipherText, key2, iv2);

        act.Should().Throw<Exception>();
    }

    [Test]
    public void EncryptToBase64String_ShouldMatchCipherText_WhenUsingSameKeyIV()
    {
        var myEmail = "test@test.com";

        var (myEmailCipherText, key, iv) = EncryptAes.EncryptToBase64String(myEmail);
        var myEmailCipherText2 = EncryptAes.EncryptToBase64String(myEmail, key, iv);

        myEmailCipherText2.Should().BeEquivalentTo(myEmailCipherText);
    }

    [Test]
    public void EncryptToBase64String_ShouldNotMatchCipherText_WhenUsingDifferentKeyIV()
    {
        var myEmail = "test@test.com";

        var (myEmailCipherText, key, iv) = EncryptAes.EncryptToBase64String(myEmail);
        var (myEmailCipherText2, key2, iv2) = EncryptAes.EncryptToBase64String(myEmail);

        myEmailCipherText2.Should().NotBeEquivalentTo(myEmailCipherText);
    }

    [Test]
    public void EncryptToBase64String_ShouldDecryptCipherText()
    {
        var myEmail = "test@test.com";

        var (myEmailCipherText, key, iv) = EncryptAes.EncryptToBase64String(myEmail);

        var decryptMyEmail = EncryptAes.Decrypt(myEmailCipherText, key, iv);

        decryptMyEmail.Should().BeEquivalentTo(myEmail);
    }

    [Test]
    public void EncryptToBase64String_ShouldThrowException_WhenDecryptingUsingDifferentKeyIV()
    {
        var myEmail = "test@test.com";

        var (myEmailCipherText, key, iv) = EncryptAes.EncryptToBase64String(myEmail);

        var (key2, iv2) = EncryptAes.GenerateBase64StringKeyIV();

        Action act = () => EncryptAes.Decrypt(myEmailCipherText, key2, iv2);

        act.Should().Throw<Exception>();
    }
}