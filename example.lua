--if true then return end
require("query")
query.EnableInfoDetour(true)

print("Detour enabled")
hook.Add("A2S_INFO", "reply", function(ip, port, info)
    print("A2S_INFO from", ip, port)
    info.players = 100
    return info
end)

hook.Add("A2S_PLAYER", "reply", function(ip, port, info)
    print("A2S_PLAYER from", ip, port)
    return {
        {name = "DUCKS", score = 10, time = 10},
        {name = "DUCKS", score = 10, time = 10},
        {name = "DUCKS", score = 10, time = 10},
    }
end)