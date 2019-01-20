if (!istable(floodgate)) then
	require("floodgate")
end

--# At most 500 messages can be sent per second
timer.Create("gmsv_floodgate", 1, 0, function()
	ConsoleFloodgate(500)
end)