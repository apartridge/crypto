module crypto.blockcipher.blockcipher;

public interface BlockCipher
{
    public void encrypt(ubyte[] message);
    public void decrypt(ubyte[] cipher);

    @property public const uint blockSize();
}
