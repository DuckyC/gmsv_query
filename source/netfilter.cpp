#include <netfilter.hpp>
#include <main.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <stdint.h>
#include <stddef.h>
#include <set>
#include <queue>
#include <string>
#include <eiface.h>
#include <filesystem_stdio.h>
#include <iserver.h>
#include <iclient.h>
#include <inetchannel.h>
#include <inetchannelinfo.h>
#include "cdll_int.h"
#include <threadtools.h>
#include <utlvector.h>
#include <bitbuf.h>
#include <steam/steamclientpublic.h>
#include <steam/steam_gameserver.h>
#include <GarrysMod/Interfaces.hpp>
#include <symbolfinder.hpp>
#include <game/server/iplayerinfo.h>

#define max(a,b)            (((a) > (b)) ? (a) : (b))
#define min(a,b)            (((a) < (b)) ? (a) : (b))

#if defined _WIN32

#include <winsock2.h>

#elif defined __linux

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#elif defined __APPLE__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#endif

namespace netfilter
{

	typedef int32_t(*Hook_recvfrom_t)(
		int32_t s,
		char *buf,
		int32_t buflen,
		int32_t flags,
		sockaddr *from,
		int32_t *fromlen
		);

	struct netsocket_t
	{
		int32_t nPort;
		bool bListening;
		int32_t hUDP;
		int32_t hTCP;
	};

	struct reply_info_t
	{
		bool defaultGameName;
		std::string gameName;

		bool defaultMapName;
		std::string mapName;

		bool defaultGameDir;
		std::string gameDir;

		bool defaultGamemodeName;
		std::string gamemodeName;

		bool defaultAmtClients;
		int32_t amtClients;

		bool defaultMaxClients;
		int32_t maxClients;

		bool defaultAmtBots;
		int32_t amtBots;

		bool defaultServerType;
		char serverType;

		bool defaultOSType;
		char OSType;

		bool defaultPassworded;
		bool passworded;

		bool defaultSecure;
		bool secure;

		bool defaultGameVersion;
		std::string gameVersion;

		bool defaultUDPPort;
		int32_t UDPPort;

		bool defaultTags;
		std::string tags;

		bool defaultAppid;
		int32_t appid;

		bool defaultSteamid;
		uint64_t steamid;
	};


	struct player_t
	{
		byte index;
		std::string name;
		double score;
		double time;

	};

	struct reply_player_t
	{
		byte count;
		std::vector<player_t> players;
	};

	enum PacketType
	{
		PacketTypeIgnore = -1,
		PacketTypeGood,
		PacketTypeInfo,
		PacketTypePlayer,
		PacketTypeFake,
	};

	enum HookReply {
		HookReplyIgnore,
		HookReplyDefault,
		HookReplyFake,
	};

	typedef CUtlVector<netsocket_t> netsockets_t;

	static char hook_name[] = "A2S_REQUEST";
	static const char *default_game_version = "16.02.26";
	static const uint8_t default_proto_version = 17;

#if defined _WIN32

	static const char FileSystemFactory_sym[] = "\x55\x8B\xEC\x56\x8B\x75\x08\x68\x2A\x2A\x2A\x2A\x56\xE8";
	static const size_t FileSystemFactory_symlen = sizeof(FileSystemFactory_sym) - 1;

	static const char g_pFullFileSystem_sym[] = "@g_pFullFileSystem";
	static const size_t g_pFullFileSystem_symlen = 0;

	static const char net_sockets_sig[] = "\x2A\x2A\x2A\x2A\x80\x7E\x04\x00\x0F\x84\x2A\x2A\x2A\x2A\xA1\x2A\x2A\x2A\x2A\xC7\x45\xF8\x10";
	static size_t net_sockets_siglen = sizeof(net_sockets_sig) - 1;

	static const char IServer_sig[] = "\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\xD8\x6D\x24\x83\x4D\xEC\x10";
	static const size_t IServer_siglen = sizeof(IServer_sig) - 1;

	static const char operating_system_char = 'w';

#elif defined __linux

	static const char FileSystemFactory_sym[] = "@_Z17FileSystemFactoryPKcPi";
	static const size_t FileSystemFactory_symlen = 0;

	static const char g_pFullFileSystem_sym[] = "@g_pFullFileSystem";
	static const size_t g_pFullFileSystem_symlen = 0;

	static const char net_sockets_sig[] = "@_ZL11net_sockets";
	static const size_t net_sockets_siglen = 0;

	static const char IServer_sig[] = "@sv";
	static const size_t IServer_siglen = sizeof(IServer_sig) - 1;

	static const char operating_system_char = 'l';

#elif defined __APPLE__

	static const char FileSystemFactory_sym[] = "@_Z17FileSystemFactoryPKcPi";
	static const size_t FileSystemFactory_symlen = 0;

	static const char g_pFullFileSystem_sym[] = "@g_pFullFileSystem";
	static const size_t g_pFullFileSystem_symlen = 0;

	static const char net_sockets_sig[] = "@_ZL11net_sockets";
	static const size_t net_sockets_siglen = 0;

	static const char IServer_sig[] = "@sv";
	static const size_t IServer_siglen = sizeof(IServer_sig) - 1;

	static const char operating_system_char = 'm';

#endif

	static std::string dedicated_binary = helpers::GetBinaryFileName("dedicated", false, true, "bin/");
	static SourceSDK::FactoryLoader server_loader("server", false, true, "garrysmod/bin/");

	static Hook_recvfrom_t Hook_recvfrom = VCRHook_recvfrom;
	static int32_t game_socket = -1;

	static bool info_detour_enabled = false;
	static bool player_detour_enabled = false;
	static double info_max_requests = 60;
	static double player_max_requests = 60;

	static bool info_packet_old = false;
	static reply_info_t reply_info_fake;
	static reply_info_t reply_info_real;
	static char info_cache_buffer[1024] = { 0 };
	static bf_write info_cache_packet(info_cache_buffer, sizeof(info_cache_buffer));

	static bool player_packet_old = false;
	static reply_player_t reply_player;
	static char player_cache_buffer[1024] = { 0 };
	static bf_write player_cache_packet(player_cache_buffer, sizeof(player_cache_buffer));

	static IServer *server = nullptr;
	static IPlayerInfoManager *playerinfo = nullptr;
	static CGlobalVars *globalvars = nullptr;
	static IServerGameDLL *gamedll = nullptr;
	static IVEngineServer *engine_server = nullptr;
	static IFileSystem *filesystem = nullptr;
	static GarrysMod::Lua::ILuaInterface *lua = nullptr;

	static void BuildStaticReplyInfo()
	{
		reply_info_real.defaultGameName = true;
		reply_info_real.defaultMapName = true;
		reply_info_real.defaultGameDir = true;
		reply_info_real.defaultGamemodeName = true;
		reply_info_real.defaultAmtClients = true;
		reply_info_real.defaultMaxClients = true;
		reply_info_real.defaultAmtBots = true;
		reply_info_real.defaultServerType = true;
		reply_info_real.defaultOSType = true;
		reply_info_real.defaultPassworded = true;
		reply_info_real.defaultSecure = true;
		reply_info_real.defaultGameVersion = true;
		reply_info_real.defaultUDPPort = true;
		reply_info_real.defaultTags = true;
		reply_info_real.defaultAppid = true;
		reply_info_real.defaultSteamid = true;

		{
			reply_info_real.gameDir.resize(256);
			engine_server->GetGameDir(&reply_info_real.gameDir[0], reply_info_real.gameDir.size());
			reply_info_real.gameDir.resize(strlen(reply_info_real.gameDir.c_str()));

			size_t pos = reply_info_real.gameDir.find_last_of("\\/");
			if (pos != reply_info_real.gameDir.npos)
				reply_info_real.gameDir.erase(0, pos + 1);
		}
		{
			const IGamemodeSystem::Information &gamemode =
				static_cast<CFileSystem_Stdio *>(filesystem)->Gamemodes()->Active();

			reply_info_real.tags = " gm:";
			reply_info_real.tags += gamemode.name;

			if (!gamemode.workshopid.empty())
			{
				reply_info_real.tags += " gmws:";
				reply_info_real.tags += gamemode.workshopid;
			}
		}
		{
			FileHandle_t file = filesystem->Open("steam.inf", "r", "GAME");
			if (file == nullptr)
			{
				reply_info_real.gameVersion = default_game_version;
				DebugWarning("[Query] Error opening steam.inf\n");
				return;
			}

			char buff[256] = { 0 };
			bool failed = filesystem->ReadLine(buff, sizeof(buff), file) == nullptr;
			filesystem->Close(file);
			if (failed)
			{
				reply_info_real.gameVersion = default_game_version;
				DebugWarning("[Query] Failed reading steam.inf\n");
				return;
			}

			reply_info_real.gameVersion = &buff[13];

			size_t pos = reply_info_real.gameVersion.find_first_of("\r\n");
			if (pos != reply_info_real.gameVersion.npos)
				reply_info_real.gameVersion.erase(pos);
		}

		reply_info_real.gamemodeName = gamedll->GetGameDescription();
		reply_info_real.maxClients = server->GetMaxClients();
		reply_info_real.UDPPort = server->GetUDPPort();
		reply_info_real.OSType = operating_system_char;
		reply_info_real.serverType = 'd';
		info_packet_old = true;
	}

	static void BuildDynamicReplyInfo()
	{
		reply_info_real.gameName = server->GetName();
		reply_info_real.mapName = server->GetMapName();
		reply_info_real.amtClients = server->GetNumClients();
		reply_info_real.amtBots = server->GetNumFakeClients();
		reply_info_real.passworded = server->GetPassword() != nullptr ? 1 : 0;
		reply_info_real.secure = SteamGameServer_BSecure();
		reply_info_real.appid = engine_server->GetAppID();

		const CSteamID *sid = engine_server->GetGameServerSteamID();
		uint64_t steamid = 0;
		if (sid != nullptr)
			steamid = sid->ConvertToUint64();

		reply_info_real.steamid = steamid;

		info_packet_old = true;
	}

	static void BuildInfoPacket()
	{
		info_cache_packet.Reset();

		info_cache_packet.WriteLong(-1); // connectionless packet header
		info_cache_packet.WriteByte('I'); // packet type is always 'I'
		info_cache_packet.WriteByte(default_proto_version);

		info_cache_packet.WriteString(reply_info_real.defaultGameName ? reply_info_real.gameName.c_str() : reply_info_fake.gameName.c_str());
		info_cache_packet.WriteString(reply_info_real.defaultMapName ? reply_info_real.mapName.c_str() : reply_info_fake.mapName.c_str());
		info_cache_packet.WriteString(reply_info_real.defaultGameDir ? reply_info_real.gameDir.c_str() : reply_info_fake.gameDir.c_str());
		info_cache_packet.WriteString(reply_info_real.defaultGamemodeName ? reply_info_real.gamemodeName.c_str() : reply_info_fake.gamemodeName.c_str());

		info_cache_packet.WriteShort(reply_info_real.defaultAppid ? reply_info_real.appid : reply_info_fake.appid);

		info_cache_packet.WriteByte(reply_info_real.defaultAmtClients ? reply_info_real.amtClients : reply_info_fake.amtClients);
		info_cache_packet.WriteByte(reply_info_real.defaultMaxClients ? reply_info_real.maxClients : reply_info_fake.maxClients);
		info_cache_packet.WriteByte(reply_info_real.defaultAmtBots ? reply_info_real.amtBots : reply_info_fake.amtBots);
		info_cache_packet.WriteByte(reply_info_real.defaultServerType ? reply_info_real.serverType : reply_info_fake.serverType);
		info_cache_packet.WriteByte(reply_info_real.defaultOSType ? reply_info_real.OSType : reply_info_fake.OSType);
		info_cache_packet.WriteByte(reply_info_real.defaultPassworded ? reply_info_real.passworded : reply_info_fake.passworded);

		// if vac protected, it activates itself some time after startup
		info_cache_packet.WriteByte(reply_info_real.defaultSecure ? reply_info_real.secure : reply_info_fake.secure);
		info_cache_packet.WriteString(reply_info_real.defaultGameVersion ? reply_info_real.gameVersion.c_str() : reply_info_fake.gameVersion.c_str());

		if (reply_info_real.tags.empty())
		{
			// 0x80 - port number is present
			// 0x10 - server steamid is present
			// 0x01 - game long appid is present
			info_cache_packet.WriteByte(0x80 | 0x10 | 0x01);
			info_cache_packet.WriteShort(reply_info_real.defaultUDPPort ? reply_info_real.UDPPort : reply_info_fake.UDPPort);
			info_cache_packet.WriteLongLong(reply_info_real.defaultSteamid ? reply_info_real.steamid : reply_info_fake.steamid);
			info_cache_packet.WriteLongLong(reply_info_real.defaultAppid ? reply_info_real.appid : reply_info_fake.appid);
		}
		else
		{
			// 0x80 - port number is present
			// 0x10 - server steamid is present
			// 0x20 - tags are present
			// 0x01 - game long appid is present
			info_cache_packet.WriteByte(0x80 | 0x10 | 0x20 | 0x01);
			info_cache_packet.WriteShort(reply_info_real.defaultUDPPort ? reply_info_real.UDPPort : reply_info_fake.UDPPort);
			info_cache_packet.WriteLongLong(reply_info_real.defaultSteamid ? reply_info_real.steamid : reply_info_fake.steamid);
			info_cache_packet.WriteString(reply_info_real.defaultTags ? reply_info_real.tags.c_str() : reply_info_fake.tags.c_str());
			info_cache_packet.WriteLongLong(reply_info_real.defaultAppid ? reply_info_real.appid : reply_info_fake.appid);
		}
		info_packet_old = false;
	}

	static void BuildPlayerPacket()
	{
		reply_player_t r_player = reply_player;
		player_cache_packet.Reset();

		player_cache_packet.WriteLong(-1); // connectionless packet header
		player_cache_packet.WriteByte('D'); // packet type is always 'I'

		player_cache_packet.WriteByte(r_player.count);
		for (int i = 0; i < r_player.count; i++)
		{
			player_t player = r_player.players[i];
			player_cache_packet.WriteByte(i);
			player_cache_packet.WriteString(player.name.c_str());
			player_cache_packet.WriteLong(player.score);
			player_cache_packet.WriteFloat(player.time);
		}
		player_packet_old = false;
	}

	PacketType CallRequestHook(const sockaddr_in &from, PacketType type)
	{
		lua->GetField(GarrysMod::Lua::INDEX_GLOBAL, "hook");
		if (!lua->IsType(-1, GarrysMod::Lua::Type::TABLE))
		{
			lua->ErrorNoHalt("[QUERY] Global hook is not a table!\n");
			lua->Pop(2);
			return PacketTypeGood;
		}

		lua->GetField(-1, "Run");
		lua->Remove(-2);
		if (!lua->IsType(-1, GarrysMod::Lua::Type::FUNCTION))
		{
			lua->ErrorNoHalt("[QUERY] Global hook.Run is not a function!\n");
			lua->Pop(2);
			return PacketTypeGood;
		}

		lua->PushString(hook_name);
		lua->PushString(inet_ntoa(from.sin_addr));
		lua->PushNumber(27015);
		lua->PushNumber(type);

		if (lua->PCall(4, 1, 0) != 0)
			lua->ErrorNoHalt("\n[QUERY] %s : %s\n\n", hook_name, lua->GetString(-1));

		if (lua->IsType(-1, GarrysMod::Lua::Type::NUMBER))
		{
			double reply_type = lua->GetNumber(-1);
			lua->Pop(1);
			if (reply_type == HookReplyIgnore)
				return PacketTypeIgnore;
			if (reply_type == HookReplyDefault)
				return PacketTypeGood;
			if (reply_type == HookReplyFake)
				return PacketTypeFake;

			return PacketTypeGood;
		}

		lua->Pop(1);
		return PacketTypeGood;
	}

	static PacketType HandleInfoQuery(const sockaddr_in &from)
	{
		//TODO: DO TIMER
		PacketType type = CallRequestHook(from, PacketTypeInfo);
		if (type != PacketTypeFake)
			return type;

		BuildDynamicReplyInfo(); // update on timer

		if (info_packet_old)
			BuildInfoPacket();

		sendto(
			game_socket,
			reinterpret_cast<char *>(info_cache_packet.GetData()),
			info_cache_packet.GetNumBytesWritten(),
			0,
			reinterpret_cast<const sockaddr *>(&from),
			sizeof(from)
			);

		return PacketTypeIgnore; // we've handled it
	}

	static PacketType HandlePlayerQuery(const sockaddr_in &from)
	{
		//TODO: DO TIMER

		PacketType type = CallRequestHook(from, PacketTypePlayer);
		if (type != PacketTypeFake)
			return type;

		if (player_packet_old)
			BuildPlayerPacket();

		
		sendto(
			game_socket,
			reinterpret_cast<char *>(player_cache_packet.GetData()),
			player_cache_packet.GetNumBytesWritten(),
			0,
			reinterpret_cast<const sockaddr *>(&from),
			sizeof(from)
			);

		return PacketTypeIgnore; // we've handled it
	}

	static PacketType ClassifyPacket(const char *data, int32_t len, const sockaddr_in &from)
	{
		if (len == 0)
		{
			DebugWarning(
				"[Query] Bad OOB! len: %d from %s\n",
				len,
				inet_ntoa(from.sin_addr)
				);
			return PacketTypeIgnore;
		}

		if (len < 5)
			return PacketTypeGood;

		int32_t channel = *reinterpret_cast<const int32_t *>(data);
		if (channel == -2)
		{
			DebugWarning(
				"[Query] Bad OOB! len: %d, channel: 0x%X from %s\n",
				len,
				channel,
				inet_ntoa(from.sin_addr)
				);
			return PacketTypeIgnore;
		}

		if (channel != -1)
			return PacketTypeGood;

		int challenge = *reinterpret_cast<const int *>(data + 5);
		if (challenge == -1)
			return PacketTypeGood; // default challenge response

		uint8_t type = *reinterpret_cast<const uint8_t *>(data + 4);
		if (type == 'T')
			return PacketTypeInfo;
		if (type == 'U')
			return PacketTypePlayer;

		return PacketTypeGood;
	}

	inline int32_t ReceiveAndAnalyzePacket(int32_t s, char *buf, int32_t buflen, int32_t flags, sockaddr *from, int32_t *fromlen)
	{
		sockaddr_in &infrom = *reinterpret_cast<sockaddr_in *>(from);
		int32_t len = Hook_recvfrom(s, buf, buflen, flags, from, fromlen);
		if (len == -1)
			return -1;

		PacketType type = ClassifyPacket(buf, len, infrom);
		if (type == PacketTypeInfo && info_detour_enabled)
			return HandleInfoQuery(infrom);

		if (type == PacketTypePlayer && player_detour_enabled)
			return  HandlePlayerQuery(infrom);

		if (type == PacketTypeIgnore)
			return -1;

		return len;
	}

	inline int32_t HandleNetError(int32_t value)
	{
		if (value == -1)

#if defined _WIN32

			WSASetLastError(WSAEWOULDBLOCK);

#elif defined __linux || defined __APPLE__

			errno = EWOULDBLOCK;

#endif

		return value;
	}

	static int32_t Hook_recvfrom_d(int32_t s, char *buf, int32_t buflen, int32_t flags, sockaddr *from, int32_t *fromlen)
	{
		return HandleNetError(ReceiveAndAnalyzePacket(s, buf, buflen, flags, from, fromlen));
	}

	inline void UpdateDetourStatus()
	{
		if (info_detour_enabled || player_detour_enabled)
			VCRHook_recvfrom = Hook_recvfrom_d;
		else
			VCRHook_recvfrom = Hook_recvfrom;
	}

	LUA_FUNCTION_STATIC(EnableInfoDetour)
	{
		LUA->CheckType(1, GarrysMod::Lua::Type::BOOL);
		info_detour_enabled = LUA->GetBool(1);
		UpdateDetourStatus();
		return 0;
	}

	LUA_FUNCTION_STATIC(MaxInfoRequests)
	{
		LUA->CheckType(1, GarrysMod::Lua::Type::NUMBER);
		info_max_requests = LUA->GetNumber(1);
		return 0;
	}

	LUA_FUNCTION_STATIC(MaxPlayerRequests)
	{
		LUA->CheckType(1, GarrysMod::Lua::Type::NUMBER);
		player_max_requests = LUA->GetNumber(1);
		return 0;
	}

	LUA_FUNCTION_STATIC(SetServerName)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultGameName = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::STRING)) {
			reply_info_fake.gameName = LUA->GetString(1);
			reply_info_real.defaultGameName = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or string");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetMapName)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultMapName = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::STRING)) {
			reply_info_fake.mapName = LUA->GetString(1);
			reply_info_real.defaultMapName = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or string");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetFolderName)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultGameDir = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::STRING)) {
			reply_info_fake.gameDir = LUA->GetString(1);
			reply_info_real.defaultGameDir = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or string");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetGamemodeName)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultGamemodeName = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::STRING)) {
			reply_info_fake.gamemodeName = LUA->GetString(1);
			reply_info_real.defaultGamemodeName = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or string");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetAmountPlayers)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultAmtClients = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::NUMBER)) {
			reply_info_fake.amtClients = max(0, min(LUA->GetNumber(1), 255));
			reply_info_real.defaultAmtClients = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or number");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetMaxPlayers)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultMaxClients = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::NUMBER)) {
			reply_info_fake.maxClients = max(0, min(LUA->GetNumber(1), 255));
			reply_info_real.defaultMaxClients = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or number");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetAmountBots)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultAmtBots = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::NUMBER)) {
			reply_info_fake.amtBots = max(0, min(LUA->GetNumber(1), 255));
			reply_info_real.defaultAmtBots = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or number");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetServerType)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultServerType = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::STRING)) {
			reply_info_fake.serverType = LUA->GetString(1)[0];
			reply_info_real.defaultServerType = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or string");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetOSType)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultOSType = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::STRING)) {
			reply_info_fake.OSType = LUA->GetString(1)[0];
			reply_info_real.defaultOSType = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or string");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetPassworded)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultPassworded = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::BOOL)) {
			reply_info_fake.passworded = LUA->GetBool(1);
			reply_info_real.defaultPassworded = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or bool");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetVACEnabled)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultSecure = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::BOOL)) {
			reply_info_fake.secure = LUA->GetBool(1);
			reply_info_real.defaultSecure = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or bool");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetGameVersion)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultGameVersion = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::STRING)) {
			reply_info_fake.gameVersion = LUA->GetString(1);
			reply_info_real.defaultGameVersion = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or string");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetGamePort)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultUDPPort = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::NUMBER)) {
			reply_info_fake.UDPPort = LUA->GetNumber(1);
			reply_info_real.defaultUDPPort = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or number");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetTags)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultTags = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::STRING)) {
			reply_info_fake.tags = LUA->GetString(1);
			reply_info_real.defaultTags = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or string");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetAppID)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultAppid = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::NUMBER)) {
			reply_info_fake.appid = LUA->GetNumber(1);
			reply_info_real.defaultAppid = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or number");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetSteamID)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			reply_info_real.defaultSteamid = true;
			info_packet_old = true;
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::STRING)) {
			reply_info_fake.steamid = _strtoui64(LUA->GetString(1), 0, 10);
			reply_info_real.defaultSteamid = false;
			info_packet_old = true;
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or string");
		return 0;
	}

	LUA_FUNCTION_STATIC(SetPlayerInfo)
	{
		if (LUA->Top() == 0 || LUA->IsType(1, GarrysMod::Lua::Type::NIL))
		{
			player_detour_enabled = false;
			UpdateDetourStatus();
			return 0;
		}
		else if (LUA->IsType(1, GarrysMod::Lua::Type::TABLE)) {

			reply_player_t newreply;

			int count = lua->ObjLen(1);
			newreply.count = count;
			std::vector<player_t> newPlayers(count);

			for (int i = 0; i < count; i++)
			{
				player_t newPlayer;
				newPlayer.index = i;

				lua->PushNumber(i + 1);
				lua->GetTable(-2);

				lua->GetField(-1, "name");
				newPlayer.name = lua->GetString(-1);
				lua->Pop(1);

				lua->GetField(-1, "score");
				newPlayer.score = lua->GetNumber(-1);
				lua->Pop(1);

				lua->GetField(-1, "time");
				newPlayer.time = lua->GetNumber(-1);
				lua->Pop(1);

				lua->Pop(1);
				newPlayers.at(i) = newPlayer;
			}

			newreply.players = newPlayers;
			lua->Pop(1);

			reply_player = newreply;

			player_detour_enabled = true;
			player_packet_old = true;
			UpdateDetourStatus();
			return 0;
		}
		LUA->ArgError(1, "Argument must be nil or table");
		return 0;
	}

	void Initialize(lua_State *state)
	{
		lua = static_cast<GarrysMod::Lua::ILuaInterface *>(LUA);

		if (!server_loader.IsValid())
			LUA->ThrowError("unable to get server factory");

		gamedll = server_loader.GetInterface<IServerGameDLL>(INTERFACEVERSION_SERVERGAMEDLL_VERSION_9);
		if (gamedll == nullptr)
			LUA->ThrowError("failed to load required IServerGameDLL interface");

		engine_server = global::engine_loader.GetInterface<IVEngineServer>(
			INTERFACEVERSION_VENGINESERVER_VERSION_21
			);
		if (engine_server == nullptr)
			LUA->ThrowError("failed to load required IVEngineServer interface");

		playerinfo = server_loader.GetInterface<IPlayerInfoManager>(
			INTERFACEVERSION_PLAYERINFOMANAGER
			);
		if (playerinfo == nullptr)
			LUA->ThrowError("failed to load required IPlayerInfoManager interface");

		globalvars = playerinfo->GetGlobalVars();
		if (globalvars == nullptr)
			LUA->ThrowError("failed to load required CGlobalVars interface");

		SymbolFinder symfinder;

		CreateInterfaceFn factory = reinterpret_cast<CreateInterfaceFn>(symfinder.ResolveOnBinary(
			dedicated_binary.c_str(), FileSystemFactory_sym, FileSystemFactory_symlen
			));
		if (factory == nullptr)
		{
			IFileSystem **filesystem_ptr = reinterpret_cast<IFileSystem **>(symfinder.ResolveOnBinary(
				dedicated_binary.c_str(), g_pFullFileSystem_sym, g_pFullFileSystem_symlen
				));
			filesystem = filesystem_ptr != nullptr ? *filesystem_ptr : nullptr;
		}
		else
		{
			filesystem = static_cast<IFileSystem *>(factory(FILESYSTEM_INTERFACE_VERSION, nullptr));
		}

		if (filesystem == nullptr)
			LUA->ThrowError("failed to initialize IFileSystem");

#if defined __linux || defined __APPLE__

		server = reinterpret_cast<IServer *>(symfinder.ResolveOnBinary(
			global::engine_lib.c_str(),
			IServer_sig,
			IServer_siglen
			));

#else

		server = *reinterpret_cast<IServer **>(symfinder.ResolveOnBinary(
			global::engine_lib.c_str(),
			IServer_sig,
			IServer_siglen
			));

#endif

		if (server == nullptr)
			LUA->ThrowError("failed to locate IServer");

#if defined __linux || defined __APPLE__

		netsockets_t *net_sockets = reinterpret_cast<netsockets_t *>(symfinder.ResolveOnBinary(
			global::engine_lib.c_str(),
			net_sockets_sig,
			net_sockets_siglen
			));

#else

		netsockets_t *net_sockets = *reinterpret_cast<netsockets_t **>(symfinder.ResolveOnBinary(
			global::engine_lib.c_str(),
			net_sockets_sig,
			net_sockets_siglen
			));

#endif

		if (net_sockets == nullptr)
			LUA->ThrowError("got an invalid pointer to net_sockets");

		game_socket = net_sockets->Element(1).hUDP;
		if (game_socket == -1)
			LUA->ThrowError("got an invalid server socket");

		BuildStaticReplyInfo();

		LUA->PushCFunction(EnableInfoDetour);
		LUA->SetField(-2, "EnableInfoDetour");

		LUA->PushCFunction(MaxInfoRequests);
		LUA->SetField(-2, "MaxInfoRequests");

		LUA->PushCFunction(MaxPlayerRequests);
		LUA->SetField(-2, "MaxPlayerRequests");

		LUA->PushCFunction(SetServerName);
		LUA->SetField(-2, "SetServerName");

		LUA->PushCFunction(SetMapName);
		LUA->SetField(-2, "SetMapName");

		LUA->PushCFunction(SetFolderName);
		LUA->SetField(-2, "SetFolderName");

		LUA->PushCFunction(SetGamemodeName);
		LUA->SetField(-2, "SetGamemodeName");

		LUA->PushCFunction(SetAmountPlayers);
		LUA->SetField(-2, "SetAmountPlayers");

		LUA->PushCFunction(SetMaxPlayers);
		LUA->SetField(-2, "SetMaxPlayers");

		LUA->PushCFunction(SetAmountBots);
		LUA->SetField(-2, "SetAmountBots");

		LUA->PushCFunction(SetServerType);
		LUA->SetField(-2, "SetServerType");

		LUA->PushCFunction(SetOSType);
		LUA->SetField(-2, "SetOSType");

		LUA->PushCFunction(SetPassworded);
		LUA->SetField(-2, "SetPassworded");

		LUA->PushCFunction(SetVACEnabled);
		LUA->SetField(-2, "SetVACEnabled");

		LUA->PushCFunction(SetGameVersion);
		LUA->SetField(-2, "SetGameVersion");

		LUA->PushCFunction(SetGamePort);
		LUA->SetField(-2, "SetGamePort");

		LUA->PushCFunction(SetTags);
		LUA->SetField(-2, "SetTags");

		LUA->PushCFunction(SetAppID);
		LUA->SetField(-2, "SetAppID");

		LUA->PushCFunction(SetSteamID);
		LUA->SetField(-2, "SetSteamID");

		LUA->PushCFunction(SetPlayerInfo);
		LUA->SetField(-2, "SetPlayerInfo");
	}

	void Deinitialize(lua_State *)
	{
		VCRHook_recvfrom = Hook_recvfrom;
	}

}
