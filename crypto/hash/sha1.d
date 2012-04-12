module crypto.hash.sha1;

/*
Implements RFC 3174 - US Secure Hash Algorithm 1 (SHA1)
*/

private import crypto.hash.base;
private import std.bitmanip;

import io = std.stdio;

class SHA1 : Hash
{
	public override @property uint digestLength(){
		return 160;
	}

	private const uint iv[5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

	public override ubyte[] digest()
	{
		return [0];
	}

	private uint circularRotLeft(int positions)(const uint value)
	{
		static if(true){
			return value << positions | value >> (32-positions); // faster than & with mask? todo check // Todo add ASM ROTL instruction here ...
		}
	}

	protected override void putData(const(ubyte)[] data)
	{
		int zeros = 56 - (data.length+1) % 64;
		if(zeros < 0)
		{
			zeros += 64;
		}

		// Create new ubyte arr that contains our data

		ulong messagelength = data.length << 3;
		uint postprocbytes = data.length + 1 + zeros + 8; // bytes

		ubyte[] data2 = std.array.uninitializedArray!(ubyte[])(postprocbytes);

		data2[0..data.length] = data[]; // probably uneccessary copy

		data2[data.length] = cast(ubyte)1<<7;
		data2[data.length+1..$-8] = 0;
		data2[$-8..$] = nativeToBigEndian!ulong(messagelength);

		/*int _jx = 0;
		foreach(by; data2){
			io.write(by, "\t");
			if(++_jx == 8){
				io.writeln("");
				_jx = 0;
			}
		}*/

		uint h[5] = iv[];

		foreach(chunk; 0 .. postprocbytes/64) // for each 64 byte chunk
		{
			uint w[80] = void; // 80x32bit storage

			w[0..16] = cast(uint[]) data2[chunk*64..(chunk+1)*64];

			version(LittleEndian)
			{
				foreach(i; 0..16){
					w[i] = swapEndian(w[i]);
				}
			}

			foreach(i; 16..80) // expand from 16 to 80
			{
				w[i] = circularRotLeft!1(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
			}
			
			uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

			foreach(i; 0..80)
			{
				uint f, k;
				if(i <= 19)
				{
					f = (b & c) | ((~b) & d);
					k = 0x5a827999;
				}
				else if(i <= 39)
				{
					f = b ^ c ^ d;
					k = 0x6ed9eba1;
				}
				else if(i <= 59)
				{
					f = (b & c) | (b & d) | (c & d);
					k = 0x8f1bbcdc;
				}
				else
				{
					f = b ^ c ^ d;
					k = 0xca62c1d6;
				}

				uint temp = circularRotLeft!5(a) + f + e + k + w[i];
				e = d;
				d = c;
				c = circularRotLeft!30(b);
				b = a;
				a = temp;

			}

			h[0] += a;
			h[1] += b;
			h[2] += c;
			h[3] += d;
			h[4] += e;

		}

		version(LittleEndian)
		{
			h[0] = swapEndian(h[0]);
			h[1] = swapEndian(h[1]);
			h[2] = swapEndian(h[2]);
			h[3] = swapEndian(h[3]);
			h[4] = swapEndian(h[4]);
		}


		auto byteToHex = function(ubyte a) // 0..256
		{
			ubyte upper = (a & 0b11110000) >> 4;
			ubyte lower = a & 0b00001111;
			auto lookup = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"];

			return lookup[upper]~lookup[lower];
		};


		ubyte[] hash = cast(ubyte[]) h;

		int _j = 0;

		foreach(by; hash){
			io.write(byteToHex(by));
			if(++_j == 4){
				io.write(" ");
				_j = 0;
			}
		}

		io.writeln();


		


	}


	// Some comments
}


unittest
{
	auto sha1 = new SHA1;
	assert(sha1.circularRotLeft!1(465845615) == 931691230, "RotL1 of 465845615 does not give correct results.");
}

