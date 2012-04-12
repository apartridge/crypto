module main;

import crypto.hash.sha1;
static import std.c.stdio;

int main(string[] argv)
{
	auto sha1 = new SHA1;


	sha1.put("");
	sha1.put("The quick brown fox jumps over the lazy cog");




	return 0;
}

unittest {
	auto sha1 = new SHA1;
	assert(sha1.digestLength == 160, "SHA1 Digestlength should be 160.");
}