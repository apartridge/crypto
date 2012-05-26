module crypto.mode.cbc;

import crypto.mode.scheme;
import crypto.blockcipher.aes;
import crypto.blockcipher.blockcipher;

import std.file, std.stdio, std.array, std.stream, std.datetime;
import std.range;

class CBC : SymmetricScheme
{
    private 
    {
        ubyte[] prevBlock;
        bool atEnd;
        bool first;
    }

    this(BlockCipher cipher, ubyte[] iv, Padding pad = Padding.None)
    {
        assert(iv.length == cipher.blockSize());
        super(cipher, pad);
        this.iv = iv.dup;
        atEnd = false;
        first = true;
    }

    public override size_t _init(ubyte[] buf)
    {
        first = false;

        if (mode == Mode.Encrypt)
        {
            assert(buf.length >= iv.length);
            prevBlock = iv[];
            buf[0 .. iv.length] = iv[];
        }
        else
            prevBlock[0 .. blockSize()] = buf[0 .. blockSize()];
        return iv.length;
    }

    public override size_t _process(void[] data, void[] buf)
    {
        assert(!atEnd && !first);

        auto m = cast(ubyte[]) data;
        auto c = cast(ubyte[]) buf;

        const size_t n = cipher.blockSize();

        assert(m.length >= n);
        assert(c.length >= n);
        
        if (mode == Mode.Encrypt)
        {
            for (size_t i = 0; i < n; ++i)
                c[i] = prevBlock[i] ^ m[i];

            cipher.encrypt(c[0 .. n]);
            prevBlock = c[0 .. n].dup;
        }
        else
        {
            auto tmp = m[0 .. n].dup;
            cipher.decrypt(m[0 .. n]);

            for (size_t i = 0; i < n; ++i)
                c[i] = prevBlock[i] ^ m[i];
            prevBlock = tmp;
        }

        return n;
    }

    public override size_t _finalize(void[] data, void[] buf)
    {
        assert(!atEnd);

        ubyte[] m = cast(ubyte[]) data;
        ubyte[] c = cast(ubyte[]) buf;

        const size_t n = cipher.blockSize();
        size_t written = 0;

        if (mode == Mode.Encrypt)
        {
            assert(m.length < n);
            assert(c.length >= n);
            switch (padding)
            {
                case Padding.None:
                    if (m.length != 0)
                        throw new Exception("Invalid message size for CBC with no padding");
                    return 0;
            
                case Padding.PKCS5:
                    ubyte paddingByte = cast(ubyte)(n - m.length);
                    size_t mlen = m.length;
                    m.length = n;
                    for (uint i = mlen; i < n; ++i)
                        m[i] = paddingByte;
                    break;
            
                default:
                    break;
            }
            written = _process(m, c);
        }
        else
        {
            switch (padding)
            {
                case Padding.None:
                    if (m.length != 0)
                        throw new Exception("Invalid message size for CBC with no padding");
                    return 0;

                case Padding.PKCS5:
                    ubyte[] tmp = new ubyte[n];
                    _process(m, tmp);

                    uint dataBytes = n - cast(uint)(tmp[n-1]);
                    assert(dataBytes < n && dataBytes >= 0);

                    c[0 .. dataBytes] = tmp[0 .. dataBytes];
                    written += dataBytes;
                    break;

                default:
                    break;
            }
        }
        
        atEnd = true;
        return written;
    }

    unittest
    {
        auto cipher = new AES128(cast(ubyte[16]) x"000102030405060708090a0b0c0d0e0f");
        auto iv     = cast(ubyte[16]) x"00000000000000000000000000000000";
        auto scheme = new CBC(cipher, iv);

        const uint n = cipher.blockSize();

        auto message = (cast(ubyte[]) x"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        auto buffer = new ubyte[message.length + n];

        // Encrypt
        size_t k = scheme._init(buffer),
               i = 0;
        for (i = 0; i < message.length; i += n)
        {
            k += scheme._process(message[i .. (i+n)], buffer[k .. $]);
        }
        assert(byteToHexString(buffer) == "00000000 00000000 00000000 00000000 69c4e0d8 6a7b0430 d8cdb780 70b4c55a 7d7786be 32d059a6 0ca8021a 65dd9f09 ");

        // Decrypt
        auto decrypted = new ubyte[message.length];
        scheme.mode = SymmetricScheme.Mode.Decrypt;
        i = scheme._init(buffer), k = 0;
        for (; i < buffer.length; i += n)
        {
            k += scheme._process(buffer[i .. (i+n)], decrypted[k .. $]);
        }
        scheme._finalize(buffer[i .. $], decrypted[k .. $]);
        assert(decrypted == message, byteToHexString(decrypted));
    }
}