module crypto.mode.ecb;

import crypto.blockcipher.aes;
import crypto.blockcipher.blockcipher;

import std.file, std.stdio, std.array, std.stream, std.datetime;
import std.range;

/*
 * A symmetric encryption scheme can be defined by 
 * Mode x Blockcipher x Padding scheme x Initialization vector (IV)
 */
public abstract class SymmetricScheme
{
    public enum Padding
    {
        None,
        PKCS5
    }

    protected BlockCipher cipher;
    protected Padding padding;

    this(BlockCipher blockCipher, Padding p = Padding.None)
    {
        this.cipher = blockCipher;
        this.padding = p;
    }

    // Add blocks. End when length of m is less than block size, or call to finalize.
    // Return number of bytes written to output buffer
    public abstract size_t encrypt(void[] m, void[] buf);

    //public void decrypt(InputStream input, OutputStream output);

    public abstract size_t finalize(void[] buf);

    // Managed encrypt/decrypt for special input arguments
    public void encrypt(InputStream input, OutputStream output)
    {
        long tStart = Clock.currStdTime();
        const size_t blockSize = cipher.blockSize();
        size_t bytesRead;
        ubyte[] buffer = new ubyte[blockSize];
        ubyte[] outBuf = new ubyte[2*blockSize]; // Assumption on size

        while ((bytesRead = input.read(buffer)) > 0)
        {
            size_t k = encrypt(buffer[0 .. bytesRead], outBuf);
            output.write(outBuf[0 .. k]);
        }

        long tEnd = Clock.currStdTime();
        writeln("Encryption time: ", (tEnd - tStart)/10000000.0, " seconds");
    }
}

/*class CipherInputStream : BufferedStream
{

    unittest
    {
        auto key = cast(ubyte[16]) x"000102030405060708090a0b0c0d0e0f";
        auto iv = cast(ubyte[16]) x"00000000000000000000000000000000";
        auto scheme = new SymmetricScheme(new AES128(key), Mode.CBC, iv);
        auto fileStream = new CryptoStream(new File("in.dat"), scheme);

        while (fileStream.read()) 
        {
        }
    }
}*/


class CBC : SymmetricScheme
{
    private ubyte[] prevBlock;
    private bool atEnd;
    private bool first;

    this(BlockCipher cipher, ubyte[] iv, Padding pad = Padding.None)
    {
        assert(iv.length == cipher.blockSize());
        super(cipher, pad);
        prevBlock = new ubyte[cipher.blockSize()];
        prevBlock[] = iv[];
        atEnd = false;
        first = true;
    }

    public override size_t encrypt(void[] data, void[] buf)
    {
        assert(!atEnd);

        auto m = cast(ubyte[]) data;
        auto c = cast(ubyte[]) buf;

        const size_t n = cipher.blockSize();
        size_t written = 0;

        if (first)
        {
            assert(c.length >= n + std.algorithm.max(m.length, n));

            buf[0 .. prevBlock.length] = prevBlock[];
            written = prevBlock.length;
            first = false;
        }

        assert(c.length >= n);

        if (m.length < n)
        {
            atEnd = true;
            switch (padding)
            {
                case Padding.None:
                    throw new Exception("Invalid message size for CBC with no padding");
                case Padding.PKCS5:
                    ubyte paddingByte = cast(ubyte)(n - m.length);
                    for (uint i = m.length; i < n; ++i)
                        c[i] = paddingByte;
                    break;
                default:
                    break;
            }
        }

        for (size_t i = 0; i < n; ++i)
            c[written + i] = prevBlock[i] ^ m[i];

        cipher.encrypt(c[written .. (written + n)]);
        prevBlock = c[written .. (written + n)];

        return written + n;
    }

    public override size_t finalize(void[] buf)
    {
        atEnd = true;
        return 0;
    }

    unittest
    {
        auto cipher = new AES128(cast(ubyte[16]) x"000102030405060708090a0b0c0d0e0f");
        auto iv     = cast(ubyte[16]) x"00000000000000000000000000000000";
        auto mode = new CBC(cipher, iv);

        const uint n = cipher.blockSize();
        
        auto message = (cast(ubyte[]) x"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        auto buffer = new ubyte[message.length + n];

        //writeln("Block size: ", n, ", Message: ", message.length);
        size_t k = mode.encrypt(message[0 .. n], buffer[0 .. $]);
        for (uint i = n; i < message.length; i += n)
        {
            //writeln("Read: ", i, ", ", i+n, " . Write: ", k);
            k += mode.encrypt(message[i .. (i+n)], buffer[k .. $]);
        }
        assert(byteToHexString(buffer) == "00000000 00000000 00000000 00000000 69c4e0d8 6a7b0430 d8cdb780 70b4c55a 7d7786be 32d059a6 0ca8021a 65dd9f09 ");
    }
}

class ECB
{
    private BlockCipher blockCipher;

    this(BlockCipher bc)
    {
        blockCipher = bc;
    }

    public void encrypt(InputStream input, OutputStream output)
    {
        const uint blockSize = blockCipher.blockSize();
        ubyte[] buffer = new ubyte[blockSize];
        uint bytesRead;
        long encryptTime = 0;

        // Encrypt all whole blocks
        while ((bytesRead = input.read(buffer)) == blockSize)
        {
            long tStart = Clock.currStdTime();
            blockCipher.encrypt(buffer);
            long tEnd = Clock.currStdTime();
            encryptTime += (tEnd - tStart);
            output.write(buffer);
        }

        // Pad last block with number of padding bytes (PKCS#5)
        ubyte paddingByte = cast(ubyte)(blockSize - bytesRead);
        for (uint i = bytesRead; i < blockSize; ++i)
            buffer[i] = paddingByte;
        blockCipher.encrypt(buffer);
        output.write(buffer);

        //write("Encryption time: "); write(encryptTime / 10000000.0); writeln(" seconds");
        //blockCipher.reportTiming();
    }
    
    public void decrypt(InputStream input, OutputStream output)
    {
        const uint blockSize = blockCipher.blockSize();
        ubyte[] buffer = new ubyte[blockSize];

        while (input.read(buffer))
        {
            blockCipher.decrypt(buffer);

            // Remove padding in last block
            if (input.eof())
            {
                buffer = buffer[0 .. (blockSize-buffer[blockSize-1])];
            }
            output.write(buffer);
        }
    }

    unittest
    {
        auto cipher = new AES128(cast(ubyte[16]) x"000102030405060708090a0b0c0d0e0f");
        auto scheme = new ECB(cipher);

        auto plaintext  = cast(ubyte[]) "The quick brown fox jumped over the lazy dog";
        auto ciphertext = cast(ubyte[]) x"f7021c01de43c8147cd2477a7eba55b3 2a2fd906badb2adf811766d2aeb5cdfd 3fbc811e6a3361dadde672fad4bf4ad4";
        
        // Encrypt
        auto inputBuffer = new MemoryStream(plaintext);
        auto outputBuffer = new MemoryStream();

        scheme.encrypt(inputBuffer, outputBuffer);
        auto res = cast(ubyte[]) (outputBuffer.toString());
        assert( res == ciphertext );
        
        // Decrypt
        inputBuffer = new MemoryStream(ciphertext);
        outputBuffer = new MemoryStream();

        scheme.decrypt(inputBuffer, outputBuffer);
        res = cast(ubyte[]) (outputBuffer.toString());
        assert( res == plaintext );
    }
}
