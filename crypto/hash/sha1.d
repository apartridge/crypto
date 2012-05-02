module crypto.hash.sha1;

/*
Implements RFC 3174 - US Secure Hash Algorithm 1 (SHA1)
*/

public import crypto.hash.base;
private import std.bitmanip;
private import crypto.hash.merkle_damgaard;

version(unittest){
	private import std.stdio : writeln;
}

class SHA1 : MerkleDamgaard!(20, uint, 20, 64, 8) 
{
	protected void setInitialVector () {
		h[0] = 0x67452301;
		h[1] = 0xefcdab89;
		h[2] = 0x98badcfe;
		h[3] = 0x10325476;
		h[4] = 0xc3d2e1f0;
	}

	protected override void compress(const(ubyte)[] data, ref uint[5] h) // 512 bit to 160 bit
	{

		uint w[80] = void;

		w[0..16] = cast(uint[]) data;

		version(LittleEndian)
		{
			foreach(i; 0..16){
				w[i] = swapEndian(w[i]);
			}
		}

		foreach(i; 16..80)
		{
			w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
		}

		
		uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

		foreach(i; 0..80)
		{
			uint f, k;
			if(i <= 19)
			{
				f = b & c | ~b & d;
				k = 0x5a827999;
			}
			else if(i <= 39)
			{
				f = b ^ c ^ d;
				k = 0x6ed9eba1;
			}
			else if(i <= 59)
			{
				f = b & c | b & d | c & d;
				k = 0x8f1bbcdc;
			}
			else
			{
				f = b ^ c ^ d;
				k = 0xca62c1d6;
			}

			uint temp = rotl(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = rotl(b, 30);
			b = a;
			a = temp;

		}

		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;

	}

}

unittest
{
	assert(hashHex!SHA1("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
	auto digestBin =  hash!SHA1("");
	assert(digestBin == x"da39a3ee5e6b4b0d3255bfef95601890afd80709");
	assert(hashHex!SHA1("The quick brown fox jumps over the lazy dog") == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
	assert(hash!SHA1("The quick brown fox jumps over the lazy cog") == [222, 159, 44, 127, 210, 94, 27, 58, 250, 211, 232, 90, 11, 209, 125, 155, 16, 13, 180, 179]);
	string t512 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa64";
	assert(t512.length == 64);
	assert(hashHex!SHA1(t512) == "e22061c4fb85c3763787267adc79d566b5eb4f11");

}

// Test of putData semantics and 64B edge cases
unittest
{
	auto sha1 = new SHA1;
	assert(sha1.digest() == x"da39a3ee5e6b4b0d3255bfef95601890afd80709");
	assert(sha1.digest() == hash!SHA1(""));

	sha1.put("A");
	assert(sha1.digest() == hash!SHA1("A"));
	sha1.put("B");
	assert(sha1.digest() == hash!SHA1("AB"));

	// 63 B
	sha1.put("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDC");
	assert(sha1.digest() == hash!SHA1("ABCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDC"));

	// 64 B

	sha1.put("E");
	assert(hash!SHA1("ABCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCE") == x"dd496ae6da54a6b246d825c72c75cdb5d3e6c278");
	assert(sha1.digest() == hash!SHA1("ABCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCE"));

	// 65 B
	sha1.put("F");
	assert(hash!SHA1("ABCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCEF") == x"341f0786cb8fbf9f98039613c2ce3cfcfc11278c");
	assert(sha1.digest() == hash!SHA1("ABCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCEF"));

	sha1.put("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	sha1.put("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	sha1.put("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	sha1.put("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	sha1.put("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	sha1.put("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	sha1.put("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	sha1.put("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	sha1.put("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

	assert(sha1.digest() == x"02020a0b89972627bbbf3b9b6b139ce950d219b2");
}