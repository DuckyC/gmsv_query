if os.istarget("linux") then
	print("WARNING: The only supported compilation platforms (tested) for this project on Linux are GCC/G++ 4.8 or 4.9. However, any version between 4.4 and 4.9 *MIGHT* work.")
elseif os.istarget("macosx") then
	print("WARNING: The only supported compilation platform (tested) for this project on Mac OSX is Xcode 4.1. However, any Xcode version *MIGHT* work as long as the Mac OSX 10.5 SDK is used (-mmacosx-version-min=10.5).")
end

newoption({
	trigger = "gmcommon",
	description = "Sets the path to the garrysmod_common (https://github.com/danielga/garrysmod_common) directory",
	value = "path to garrysmod_common directory"
})

local gmcommon = _OPTIONS.gmcommon or os.getenv("GARRYSMOD_COMMON")
if gmcommon == nil then
	error("you didn't provide a path to your garrysmod_common (https://github.com/danielga/garrysmod_common) directory")
end

include(gmcommon)

CreateWorkspace({name = "query", allow_debug = false})
	filter("system:macosx")
		buildoptions("-mmacosx-version-min=10.5")
		linkoptions("-mmacosx-version-min=10.5")

	CreateProject({serverside = true})
		warnings("Default")
		IncludeSDKCommon()
		IncludeSDKTier0()
		IncludeSDKTier1()
		IncludeSteamAPI()
		IncludeDetouring()
		IncludeScanning()