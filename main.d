module main;

import crypto.hash.sha1;
import crypto.hash.sha2;
import std.stdio;

int main(string[] argv)
{

	auto sha = new SHA224;
	sha.put("");
	// 07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6
	writeln(sha.digestHex());





	return 0;
}


