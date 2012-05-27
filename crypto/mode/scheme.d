module crypto.mode.scheme;

import crypto.mode.cbc;
import crypto.blockcipher.aes;
import crypto.blockcipher.blockcipher;

import std.stdio, std.array, std.stream, std.datetime;

public abstract class SymmetricScheme
{
    public enum Padding
    {
        None,
        PKCS5
    }

    public enum Mode
    {
        Encrypt,
        Decrypt
    }

    protected BlockCipher cipher;
    protected Padding padding;
    protected ubyte[] iv;

    @property Mode mode;
    @property size_t blockSize()
    {
        return cipher.blockSize();
    }

    this(BlockCipher blockCipher, Padding p = Padding.None)
    {
        this.cipher = blockCipher;
        this.padding = p;
        this.mode = Mode.Encrypt;
    }

    public void encrypt(InputStream input, OutputStream output);

    public void decrypt(InputStream iStream, OutputStream oStream);

    static void generateIv(ubyte[] buf)
    {
        // TODO
    }
}
