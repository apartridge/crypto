module crypto.hash.base;

/*
Handles

	Receieve data from caller
	


*/

abstract class Hash
{
	abstract @property uint digestLength();
	abstract ubyte[] digest();
	
	protected abstract void finish()
	{

	}






	final string digestToHex(){
		return ""; // todo
	}
}
