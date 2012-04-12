module main;

import crypto.hash.sha1;
static import std.c.stdio;

int main(string[] argv)
{
	auto sha1 = new SHA1;
	sha1.put("The big fox leaps over the fence.");

	string hashedString = sha1.digestHex();

	return 0;
}

unittest {
	auto sha1 = new SHA1;
	assert(sha1.digestLength == 160, "Digestlength should be 160.");
}