module main;

import crypto.hash.sha1;
import std.stdio;

int main(string[] argv)
{
	auto sha1 = new SHA1;
	sha1.put("A");
	writeln(sha1.digestHex());
	return 0;
}


