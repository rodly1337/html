local excluded_functions = { 
    type = true, pairs = true, ipairs = true, next = true, select = true,
    unpack = true, tonumber = true, tostring = true, print = true,
    error = true, pcall = true, xpcall = true, rawget = true, rawset = true, 
    rawlen = true, require = true, setmetatable = true, rawequal = true,
    assert = true, collectgarbage = true, dofile = true, getmetatable = true,
    load = true, loadfile = true
}

local excluded_modules = {
    coroutine = true, debug = true, io = true, os = true, math = true, table = true, string = true
}

for k, v in pairs(_ENV) do
    if type(v) == "function" and not excluded_functions[k] and not excluded_modules[k] then
        pcall(function() _ENV[k] = function(...) return nil end end)
    end
end

for k, v in pairs(_G) do
        if type(v) == "function" and not excluded_functions[k] and not excluded_modules[k] then
            pcall(function() _G[k] = function(...) return nil end end)
        end
    end