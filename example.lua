if (!istable(query)) then
	require("query")
end

query.EnableInfoDetour(true)

print("Detour enabled")
hook.Add("A2S_INFO", "reply", function(ip, port, info)
    print("A2S_INFO from", ip, port)
	
    info.players = 100
    info.map = 'newbie'
	
    return info
end)

hook.Add("A2S_PLAYER", "reply", function(ip, port, info)
    print("A2S_PLAYER from", ip, port)
	
    return {
        {name = "DUCKS1", score = 3, time = 1},
		{name = "DUCKS2", score = 2, time = 2},
		{name = "DUCKS3", score = 1, time = 3},
    }
end)
