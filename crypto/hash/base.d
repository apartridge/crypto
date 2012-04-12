module crypto.hash.base;
import std.traits;

/*
Handles
	Receieve data from caller, store it
*/

abstract class Hash
{
	public abstract @property uint digestLength();

	public abstract ubyte[] digest();
	
	protected abstract void putData(const(ubyte)[]);

	public final void put(T)(in T data)
	{
		/*static if (isArray!T)
		{
			putData(cast(const(ubyte)[]) data);
		}
		else*/
		putData(cast(const(ubyte)[]) data);

	}

	public final string digestHex(){
		return "aabb";
	}
}
