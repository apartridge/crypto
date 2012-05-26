module crypto.mode.scheme;

import crypto.mode.cbc;
import crypto.blockcipher.aes;
import crypto.blockcipher.blockcipher;

import std.stdio, std.array, std.stream, std.datetime;


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

    public enum Mode
    {
        Encrypt,
        Decrypt
    }

    protected BlockCipher cipher;
    protected Padding padding;
    protected @property Mode mode;
    protected ubyte[] iv;

    public @property size_t blockSize()
    {
        return cipher.blockSize();
    }

    this(BlockCipher blockCipher, Padding p = Padding.None)
    {
        this.cipher = blockCipher;
        this.padding = p;
        this.mode = Mode.Encrypt;
    }

    // Initialize output
    public abstract size_t _init(ubyte[] buf);

    // Process blocks, return number of bytes written to output buffer (always block size)
    public abstract size_t _process(void[] data, void[] buf);

    // Process final block
    public abstract size_t _finalize(void[] data, void[] buf);

    static void generateIv(ubyte[] buf)
    {

    }

    // Managed encrypt/decrypt for special input arguments
    public void process(InputStream input, OutputStream output)
    {
        long tStart = Clock.currStdTime();
        const size_t n = cipher.blockSize();
        size_t bytesDone, k;
        ubyte[] inBuf  = new ubyte[n];
        ubyte[] outBuf = new ubyte[n];
/*
        if (mode == Mode.Encrypt)
            bytesDone = _init(outBuf);
        else
            bytesDone = _init(inBuf);

        while ((k = input.read(inBuf)) > 0)
        {
            size_t k = _process(inBuf[0 .. bytesRead], outBuf);
            output.write(outBuf[0 .. k]);
        }
*/
        long tEnd = Clock.currStdTime();
        writeln("Encryption time: ", (tEnd - tStart)/10000000.0, " seconds");
    }
}

/*
class CipherStream : BufferedStream
{
    private
    {
        SymmetricScheme scheme;
        ubyte[] bufferedData;
        bool first;
        bool doneLast;
    }

    public enum Mode
    {
        Read,
        Write
    }

    this(Stream wrappedStream, SymmetricScheme scheme)
    {
        const size_t preferredBufferSize = 8192u;
        super(wrappedStream, preferredBufferSize);
        this.bufferedData.length = 0;
        this.scheme = scheme;
        first = true;
        doneLast = false;
    }

    // Need to override read and writes. Now: Encrypted read file
    public override size_t read(ubyte[] buffer)
    {
        size_t read = 0, k = 0,
               written = 0,
               n = scheme.blockSize();

        // Write IV if fresh read. Might not enough buffer size to do init
        if (first)
        {
            bufferedData.length = scheme.blockSize();
            k = scheme._init(bufferedData);
            if (k <= buffer.length)
            {
                buffer[0 .. k] = bufferedData[0 .. k];
                bufferedData.length = 0;
                written += k;
            }
            else
            {
                buffer[0 .. $] = bufferedData[0 .. buffer.length];
                bufferedData = bufferedData[buffer.length .. $];
                written += buffer.length;
            }
            //writeln("Was first");
            first = false;
        }

        // Some buffered data remaining from last time, 
        // write as much as possible of that first
        if (bufferedData.length != 0)
        {
            size_t remainingBuffer = buffer.length - written;
            size_t oldDataSize = bufferedData.length;

            // Able to write all the old data
            if (remainingBuffer >= oldDataSize)
            {
                buffer[written .. written + oldDataSize] = bufferedData[];
                bufferedData.length = 0;
                written += oldDataSize;
            }

            // Not able to write all the old data
            else 
            {
                buffer[written .. $] = bufferedData[0 .. remainingBuffer];
                bufferedData = bufferedData[remainingBuffer .. $];
                written += remainingBuffer;
                return written;
            }
        }

        // Already done last, need to wait for next call to read
        if (doneLast)
            return written;

        // Read and encrypt full blocks from underlying stream, use remaining part of buffer
        while (buffer.length - written >= n)
        {
            k = super.read(buffer[written .. written+n]);

            if (k == n)
            {
                //writeln("processing ", byteToHexString(buffer[written .. written+n]));
                written += scheme._process(buffer[written .. written+n], buffer[written .. written+n]);
            }
            else
            {
                assert(source().eof());
                written += scheme._finalize(buffer[written .. written+k], buffer[written .. written+n]);
                doneLast = true;
                //writeln("EOF");
                return written;
            }
        }

        // Not enough space to process whole blocks. Process a whole new block,
        // write as much as possible to buffer, then store the remaining for next call.
        size_t availableBuffer = buffer.length - written;
        if (availableBuffer < n && availableBuffer > 0)
        {
            //writeln("Not enough space");
            ubyte[] tmp = new ubyte[scheme.blockSize()];
            k = super.read(tmp);

            if (k == n)
            {
                //writeln("processing ", byteToHexString(tmp));
                size_t w = scheme._process(tmp[0 .. k], tmp);
            
                buffer[written .. $] = tmp[0 .. availableBuffer];
                bufferedData = tmp[availableBuffer .. $];

                written += availableBuffer;
                assert(written == buffer.length);
            }
            else
            {
                assert(source().eof());
                k = scheme._finalize(tmp[0 .. k], tmp);
                buffer[written .. $] = tmp[0 .. availableBuffer];
                bufferedData = tmp[availableBuffer .. $];
                written += availableBuffer;
                doneLast = true;
                //writeln("EOF");
                return written;
            }
        }

        return written;
    }

    // Call automatically on dispose
    public size_t flushFinalBlock(ubyte[] buffer)
    {
        return (!doneLast) ? scheme._finalize(bufferedData, buffer) : 0;
    }

    public override void read(out ubyte b){}
    public override void read(out byte b){}
    void read(out short x){} 
    void read(out ushort x){} 
    void read(out int x){} 
    void read(out uint x){}
    void read(out long x){}
    void read(out ulong x){} 
    void read(out float x){}
    void read(out double x){} 
    void read(out real x){}
    void read(out ifloat x){} 
    void read(out idouble x){} 
    void read(out ireal x){} 
    void read(out cfloat x){} 
    void read(out cdouble x){} 
    void read(out creal x){} 
    void read(out char x){} 
    void read(out wchar x){} 
    void read(out dchar x){} 
    void read(out char[] s){} 
    void read(out wchar[] s){}

    unittest
    {
        auto key = cast(ubyte[16]) x"000102030405060708090a0b0c0d0e0f";
        auto iv = new ubyte[16]; // Init to zeros

        auto scheme     = new CBC(new AES128(key), iv, SymmetricScheme.Padding.PKCS5);
        auto fileStream = new CipherStream(new std.stream.File("../../scripts/plain.dat"), scheme);

        ubyte[] buf = new ubyte[5];
        ubyte[] res;
        size_t k = 0;
        while ((k = fileStream.read(buf)) > 0) 
        {
            res ~= buf[0 .. k];
        }
        assert(byteToHexString(res) == "00000000 00000000 00000000 00000000 69c4e0d8 6a7b0430 d8cdb780 70b4c55a 7d7786be 32d059a6 0ca8021a 65dd9f09 b503c779 12c4f75b 88a570aa 03738902 ", byteToHexString(res));
    }
}
*/
