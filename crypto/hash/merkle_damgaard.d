module crypto.hash.merkle_damgaard;
private import crypto.hash.base;
private import std.bitmanip;
private import std.stdio;
private import std.algorithm : min;

class MerkleDamgaard ( int outputByteSize, int blockByteSize, int messageLengthAppendixBytes ) : Hash
{
	protected abstract void compress(const(ubyte)[] block, ref uint[outputByteSize/4] ho);
	protected abstract ubyte[outputByteSize] finalize(ref uint[outputByteSize/4] hi);
	protected abstract void setInitialVector();
	protected abstract ubyte[messageLengthAppendixBytes] messageLengthAppendix(int messageLengthBytes);

	private int messageLengthBytes = 0; 
	private ubyte[blockByteSize] buffer = void;
	private int bufferUsedBytes = 0;
	protected uint[outputByteSize/4] h;

	this()
	{
		setInitialVector();
	}

	public override @property uint digestBytes(){
		return outputByteSize;
	}

	protected override void putData(const(ubyte)[] data)
	{
	
		messageLengthBytes += data.length;
		const(ubyte)[] data_aligned = data;

		if(bufferUsedBytes > 0)
		{
			int bufferUpperLimit = min(bufferUsedBytes + data.length, blockByteSize);
			buffer[bufferUsedBytes..bufferUpperLimit] = data[0..bufferUpperLimit-bufferUsedBytes];
			data_aligned = data[bufferUpperLimit-bufferUsedBytes..$];
			bufferUsedBytes = bufferUpperLimit;

			if(bufferUsedBytes < blockByteSize)
			{
				return;
			}
			
			compress(buffer, h);
		}

		foreach(block; 0..data_aligned.length/blockByteSize)
		{
			compress(data_aligned[block*blockByteSize..(block+1)*blockByteSize], h);
		}

		// Overflowing bytes, place it in the buffer

		bufferUsedBytes = data_aligned.length % blockByteSize;
		if(bufferUsedBytes > 0)
		{
			buffer[0..bufferUsedBytes] = data_aligned[$ - data_aligned.length % blockByteSize..$];
		}
		
	}

	public override ubyte[] digest()
	{

		assert(bufferUsedBytes >= 0 && bufferUsedBytes < 64);

		int zeros = blockByteSize - messageLengthAppendixBytes - 1 - bufferUsedBytes;

		uint[outputByteSize/4] h2 = h;

		if(zeros < 0)
		{
			 // We need another block for sure. Fill this first one with zeros
			ubyte[blockByteSize] extraBlock = void;
			extraBlock[0..$-messageLengthAppendixBytes-1] = 0;

			if(bufferUsedBytes < blockByteSize)
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
		
		return finalize(h2).dup;
	}

	protected uint circularRotLeft(const int positions)(const uint value)
	{
		return value << positions | value >> (32-positions);
		
	}

	~this()
	{
		// scratch buffer
		buffer[] = 0;
		messageLengthBytes = 0;
	}

}