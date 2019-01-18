#pragma once

#include <stdint.h>
#include <sstream>

namespace GarrysMod
{
	namespace Lua
	{
		class ILuaBase;
		class ILuaInterface;
	}
}

namespace netfilter
{
	void Initialize( GarrysMod::Lua::ILuaBase *LUA );
	void Deinitialize( GarrysMod::Lua::ILuaBase *LUA );
}