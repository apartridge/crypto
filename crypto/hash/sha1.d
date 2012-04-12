module crypto.hash.sha1;

private import crypto.hash.base;
static import std.bitmanip;
static import std.stdio;

class SHA1 : Hash
{
	public override @property uint digestLength(){
		return 160;
	}

	private uint iv[5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];


	public override ubyte[] digest()
	{
		return [0];
	}

	protected override void putData(const(ubyte)[] data)
	{
		int zeros = 448 - data.length % 512;
		if(zeros < 0)
		{
			zeros += 512;
		}

		// Create new ubyte arr that contains our data

		ulong messagelength = data.length << 3;

		ubyte[] data2 = std.array.uninitializedArray!(ubyte[])(data.length + zeros + 8);

		data2[0..data.length] = data[];
		data2[data.length..$-8] = 0;
	
		// Append Message Length .. 

		data2[$-8..$] = std.bitmanip.nativeToBigEndian!ulong(messagelength);

		std.stdio.writeln(data.length, " bytes of data");
		std.stdio.writeln(messagelength, " bits message");
		std.stdio.writeln(zeros, " k 0's to be added");

		int i = 0;
		foreach(b; data2){
			std.stdio.write(b, "\t");
			if(i++ == 7){
				i = 0;
				std.stdio.writeln("");
			}
		}


	}


	// Some comments
}


