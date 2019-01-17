#include <main.hpp>
#include <netfilter.hpp>
#include <GarrysMod/Lua/Interface.h>

#if defined __APPLE__

#include <AvailabilityMacros.h>

#if MAC_OS_X_VERSION_MIN_REQUIRED > 1050

#error The only supported compilation platform for this project on Mac OS X is GCC with Mac OS X 10.5 SDK (for ABI reasons).

#endif

#endif

namespace global
{

	SourceSDK::FactoryLoader engine_loader( "engine", false, true, "bin/" );
	std::string engine_lib = Helpers::GetBinaryFileName( "engine", false, true, "bin/" );

	static void PreInitialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		if( !engine_loader.IsValid( ) )
			LUA->ThrowError( "unable to get engine factory" );

		LUA->CreateTable( );

		LUA->PushString( "Query 1.1" );
		LUA->SetField( -2, "Version" );

		// version num follows LuaJIT style, xxyyzz
		LUA->PushNumber( 010000 );
		LUA->SetField( -2, "VersionNum" );
	}

	static void Initialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, "query" );
	}

	static void Deinitialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		LUA->PushNil( );
		LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, "query" );
	}

}

GMOD_MODULE_OPEN( )
{
	global::PreInitialize( LUA );
	netfilter::Initialize( LUA );
	global::Initialize( LUA );
	return 1;
}

GMOD_MODULE_CLOSE( )
{
	netfilter::Deinitialize( LUA );
	global::Deinitialize( LUA );
	return 0;
}
