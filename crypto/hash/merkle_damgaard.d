module crypto.hash.merkle_damgaard;
private import crypto.hash.d;
private import std.bitmanip;
private import std.stdio;
private import std.algorithm : min;

/*
// A Abstract Merke Damgaard Base Class
// IST is the internal data type of the hash function, uint or ulong (for SHA2).
*/

class MerkleDamgaard ( uint outputBytes, IST, uint internalStateBytes, uint blockBytes, uint messageLengthAppendixBytes ) : Hash
{
    protected abstract void compress(const(ubyte)[] block, ref IST[internalStateBytes/IST.sizeof] ho);
    protected abstract void setInitialVector();

    private ulong messageLengthBytes = 0; 
    private ubyte[blockBytes] buffer = void;
    private int bufferUsedBytes = 0;
    protected IST[internalStateBytes/IST.sizeof] h;

    this()
    {
        setInitialVector();
    }

    public override @property uint digestBytes(){
        return outputBytes;
    }

    public override void reset()
    {
        setInitialVector();
        messageLengthBytes = 0;
        bufferUsedBytes = 0;
    }

    protected override void putData(const(ubyte)[] data)
    {
    
        messageLengthBytes += data.length;
        const(ubyte)[] data_aligned = data;

        if(bufferUsedBytes > 0)
        {
            int bufferUpperLimit = min(bufferUsedBytes + data.length, blockBytes);
            buffer[bufferUsedBytes..bufferUpperLimit] = data[0..bufferUpperLimit-bufferUsedBytes];
            data_aligned = data[bufferUpperLimit-bufferUsedBytes..$];
            bufferUsedBytes = bufferUpperLimit;

            if(bufferUsedBytes < blockBytes)
            {
                return;
            }
            
            compress(buffer, h);
        }

        foreach(block; 0..data_aligned.length/blockBytes)
        {
            compress(data_aligned[block*blockBytes..(block+1)*blockBytes], h);
        }

        // Overflowing bytes, place it in the buffer

        bufferUsedBytes = data_aligned.length % blockBytes;
        if(bufferUsedBytes > 0)
        {
            buffer[0..bufferUsedBytes] = data_aligned[$ - data_aligned.length % blockBytes..$];
        }
        
    }

    protected override ubyte[] digestBuffer(ubyte[] outputbuffer)
    {
        assert(bufferUsedBytes >= 0 && bufferUsedBytes < blockBytes && outputbuffer.length >= outputBytes);

        int zeros = blockBytes - messageLengthAppendixBytes - 1 - bufferUsedBytes;

        IST[internalStateBytes/IST.sizeof] h2 = h;

        if(zeros < 0)
        {
             // We need another block for sure. Fill this first one with zeros
            ubyte[blockBytes] extraBlock = void;
            extraBlock[0..$-messageLengthAppendixBytes-1] = 0;

            if(bufferUsedBytes < blockBytes)
            {
                buffer[bufferUsedBytes] = 1<<7;
                buffer[bufferUsedBytes+1..$] = 0;
            }
            else
            {
                extraBlock[0] = 1<<7;
            }

            extraBlock[$-messageLengthAppendixBytes..$] = messageLengthAppendix(messageLengthBytes);

            compress(buffer, h2);
            compress(extraBlock, h2);

        }
        else
        {
            buffer[bufferUsedBytes] = 1<<7;
            buffer[bufferUsedBytes+1..$-messageLengthAppendixBytes] = 0;
            buffer[$-messageLengthAppendixBytes..$] = messageLengthAppendix(messageLengthBytes);            
            compress(buffer, h2);
        }
        
        finalize(h2, outputbuffer[0..outputBytes]);
        return outputbuffer[0..outputBytes];
    }

    protected void finalize(ref IST[internalStateBytes/IST.sizeof] h,
                            ubyte[] buffer)
    {  
        buffer[] = cast(ubyte[])h[0..outputBytes/IST.sizeof];
        IST[] bufferInternalStateView = cast(IST[])buffer;

        version(LittleEndian)
        {
            foreach(i; 0..outputBytes/IST.sizeof)
            {
                bufferInternalStateView[i] = swapEndian(h[i]);
            }
        }

    }

    protected ubyte[messageLengthAppendixBytes] messageLengthAppendix(ulong messageLengthBytes)
    {
        static if(messageLengthAppendixBytes == 8)
        {
            return nativeToBigEndian!ulong(messageLengthBytes << 3);
        }
        else assert (false, "messageLengthAppendix() not implemented for this messageLengthAppendixBytes!");
    }

    protected static T rotl(T)(const T value, const uint positions)
    {
        return value << positions | value >> (8*T.sizeof-positions);
    }

    protected static T rotr(T)(const T value, const uint positions)
    {
        return value >> positions | value << (8*T.sizeof-positions);
    }


    ~this()
    {
        buffer[] = 0;
        messageLengthBytes = 0;
        bufferUsedBytes = 0;
    }

}

