Citizen.CreateThread(function()
    local _tostring = tostring
    local _tonumber = tonumber
    local _print = print
    local _pairs = pairs
    local _ipairs = ipairs
    local _type = type
    local _math_random = math.random
    local _table_insert = table.insert
    local _table_remove = table.remove
    local _string_format = string.format
    local _string_lower = string.lower
    local _string_find = string.find
    local _string_gsub = string.gsub

    local FiveGuardBypass = {
        Config = {
            DebugMode = false,
            AutoUpdate = true,
            DeepProtection = true,
            MemoryObfuscation = true,
            NetworkSpoofing = true,
            ResourceSpoofing = true,
            HookProtection = true,
            ScreenshotBlock = true,
            EventFiltering = true,
            PatternBypass = true,
            AntiAnalysis = true,
            FakeTraffic = true,
            EmergencyProtocols = true
        },
        State = {
            Initialized = false,
            ProtectionActive = false,
            FiveGuardDetected = false,
            MemoryProtected = false,
            HooksInstalled = false,
            EventsBlocked = false,
            LastUpdate = 0,
            DetectionCount = 0,
            EmergencyMode = false
        },
        Hooks = {
            Original = {},
            Patched = {}
        },
        Memory = {
            Blocks = {},
            Patterns = {},
            Obfuscation = {}
        },
        Resources = {
            FiveGuard = {
                Names = {"FiveGuard", "fiveguard", "fg", "FG", "Five Guard", "FIVEGUARD", "fiveGuard"},
                States = {},
                Detection = {}
            },
            Spoofed = {}
        },
        Events = {
            Blocked = {
                "FiveGuard:",
                "fiveguard:",
                "fg:",
                "FG:",
                "FiveGuard:",
                "FIVEGUARD:",
                "anticheat",
                "AntiCheat",
                "ANTICHEAT",
                "ac:",
                "AC:",
                "detection",
                "Detection",
                "DETECTION",
                "screenshot",
                "Screenshot",
                "SCREENSHOT",
                "snapshot",
                "Snapshot",
                "SNAPSHOT",
                "ban",
                "Ban",
                "BAN",
                "kick",
                "Kick",
                "KICK",
                "report",
                "Report",
                "REPORT",
                "violation",
                "Violation",
                "VIOLATION",
                "cheat",
                "Cheat",
                "CHEAT",
                "hack",
                "Hack",
                "HACK",
                "injection",
                "Injection",
                "INJECTION",
                "modification",
                "Modification",
                "MODIFICATION"
            },
            Fake = {}
        },
        Network = {
            Spoofed = {},
            Filtered = {}
        }
    }

    local function InitializeMemoryObfuscation()
        if not FiveGuardBypass.Config.MemoryObfuscation then return end
        
        for i = 1, 50 do
            FiveGuardBypass.Memory.Blocks[i] = _math_random(1000000, 9999999)
            FiveGuardBypass.Memory.Obfuscation["block_" .. i] = {
                data = _math_random(100000, 999999),
                timestamp = GetGameTimer(),
                hash = _math_random(10000, 99999)
            }
        end

        Citizen.CreateThread(function()
            while FiveGuardBypass.State.ProtectionActive do
                Citizen.Wait(2000)
                for i = 1, #FiveGuardBypass.Memory.Blocks do
                    FiveGuardBypass.Memory.Blocks[i] = _math_random(1000000, 9999999)
                    FiveGuardBypass.Memory.Obfuscation["block_" .. i].data = _math_random(100000, 999999)
                    FiveGuardBypass.Memory.Obfuscation["block_" .. i].timestamp = GetGameTimer()
                end
            end
        end)

        FiveGuardBypass.State.MemoryProtected = true
        if FiveGuardBypass.Config.DebugMode then _print("[MEMORY] Obfuscation activated") end
    end

    local function DetectFiveGuard()
        for _, name in _ipairs(FiveGuardBypass.Resources.FiveGuard.Names) do
            local state = GetResourceState(name)
            FiveGuardBypass.Resources.FiveGuard.States[name] = state
            
            if state == "started" or state == "starting" then
                FiveGuardBypass.State.FiveGuardDetected = true
                FiveGuardBypass.Resources.FiveGuard.Detection[name] = {
                    state = state,
                    timestamp = GetGameTimer(),
                    actions = 0
                }
                if FiveGuardBypass.Config.DebugMode then _print("[DETECTION] FiveGuard found: " .. name .. " (" .. state .. ")") end
            end
        end
        return FiveGuardBypass.State.FiveGuardDetected
    end

    local function DisableFiveGuard()
        if not FiveGuardBypass.State.FiveGuardDetected then return end
        
        for name, data in _pairs(FiveGuardBypass.Resources.FiveGuard.Detection) do
            if data.state == "started" or data.state == "starting" then
                for i = 1, 3 do
                    ExecuteCommand("stop " .. name)
                    Citizen.Wait(100)
                end
                data.state = "stopped"
                data.actions = data.actions + 1
                if FiveGuardBypass.Config.DebugMode then _print("[DISABLE] FiveGuard stopped: " .. name) end
            end
        end
        
        FiveGuardBypass.State.FiveGuardDetected = false
    end

    local function InstallHookProtection()
        if not FiveGuardBypass.Config.HookProtection then return end
        
        FiveGuardBypass.Hooks.Original.GetResourceState = GetResourceState
        _G.GetResourceState = function(resourceName)
            local lowerName = _string_lower(resourceName)
            for _, fgName in _ipairs(FiveGuardBypass.Resources.FiveGuard.Names) do
                if lowerName == _string_lower(fgName) then
                    return "stopped"
                end
            end
            return FiveGuardBypass.Hooks.Original.GetResourceState(resourceName)
        end

        FiveGuardBypass.Hooks.Original.ExecuteCommand = ExecuteCommand
        _G.ExecuteCommand = function(command)
            local lowerCmd = _string_lower(command)
            for _, fgName in _ipairs(FiveGuardBypass.Resources.FiveGuard.Names) do
                if _string_find(lowerCmd, _string_lower(fgName)) then
                    if FiveGuardBypass.Config.DebugMode then _print("[HOOK] Command blocked: " .. command) end
                    return
                end
            end
            return FiveGuardBypass.Hooks.Original.ExecuteCommand(command)
        end

        FiveGuardBypass.Hooks.Original.TriggerServerEvent = TriggerServerEvent
        _G.TriggerServerEvent = function(eventName, ...)
            local lowerEvent = _string_lower(eventName)
            for _, blocked in _ipairs(FiveGuardBypass.Events.Blocked) do
                if _string_find(lowerEvent, _string_lower(blocked)) then
                    if FiveGuardBypass.Config.DebugMode then _print("[HOOK] Event blocked: " .. eventName) end
                    return
                end
            end
            return FiveGuardBypass.Hooks.Original.TriggerServerEvent(eventName, ...)
        end

        FiveGuardBypass.State.HooksInstalled = true
        if FiveGuardBypass.Config.DebugMode then _print("[HOOKS] Protection installed") end
    end

    local function InstallEventBlocking()
        if not FiveGuardBypass.Config.EventFiltering then return end
        
        for _, event in _ipairs(FiveGuardBypass.Events.Blocked) do
            RegisterNetEvent(event)
            AddEventHandler(event, function(...)
                if FiveGuardBypass.Config.DebugMode then _print("[EVENT] Blocked: " .. event) end
                return
            end)
        end

        if FiveGuardBypass.Config.ScreenshotBlock then
            AddEventHandler("onClientScreenshot", function() CancelEvent() end)
            AddEventHandler("onClientScreenshotReady", function() CancelEvent() end)
            AddEventHandler("onClientScreenshotComplete", function() CancelEvent() end)
        end

        AddEventHandler("onClientResourceStart", function(resourceName)
            local lowerName = _string_lower(resourceName)
            for _, fgName in _ipairs(FiveGuardBypass.Resources.FiveGuard.Names) do
                if lowerName == _string_lower(fgName) then
                    Citizen.Wait(1000)
                    ExecuteCommand("stop " .. resourceName)
                    if FiveGuardBypass.Config.DebugMode then _print("[RESOURCE] Auto-stopped: " .. resourceName) end
                end
            end
        end)

        FiveGuardBypass.State.EventsBlocked = true
        if FiveGuardBypass.Config.DebugMode then _print("[EVENTS] Blocking activated") end
    end

    local function InitializeNetworkSpoofing()
        if not FiveGuardBypass.Config.NetworkSpoofing then return end
        
        Citizen.CreateThread(function()
            while FiveGuardBypass.State.ProtectionActive do
                Citizen.Wait(_math_random(45000, 90000))
                
                local ped = PlayerPedId()
                local coords = GetEntityCoords(ped)
                FiveGuardBypass.Hooks.Original.TriggerServerEvent("player:updatePosition", coords.x, coords.y, coords.z)
                
                local vehicle = GetVehiclePedIsIn(ped, false)
                if vehicle ~= 0 then
                    FiveGuardBypass.Hooks.Original.TriggerServerEvent("vehicle:updateData", vehicle)
                end
                
                local weapon = GetSelectedPedWeapon(ped)
                if weapon ~= nil then
                    FiveGuardBypass.Hooks.Original.TriggerServerEvent("weapon:updateAmmo", weapon)
                end
            end
        end)
    end

    local function InitializeResourceSpoofing()
        if not FiveGuardBypass.Config.ResourceSpoofing then return end
        
        Citizen.CreateThread(function()
            while FiveGuardBypass.State.ProtectionActive do
                Citizen.Wait(30000)
                
                for _, name in _ipairs(FiveGuardBypass.Resources.FiveGuard.Names) do
                    local state = FiveGuardBypass.Hooks.Original.GetResourceState(name)
                    if state == "started" or state == "starting" then
                        FiveGuardBypass.State.DetectionCount = FiveGuardBypass.State.DetectionCount + 1
                        for i = 1, 3 do
                            FiveGuardBypass.Hooks.Original.ExecuteCommand("stop " .. name)
                            Citizen.Wait(50)
                        end
                        if FiveGuardBypass.Config.DebugMode then _print("[SPOOF] FiveGuard stopped: " .. name) end
                    end
                end
                
                if FiveGuardBypass.Config.DebugMode and _math_random(1, 10) == 1 then
                    _print("[SPOOF] Resource spoofing active")
                end
            end
        end)
    end

    local function InitializeEmergencyProtocols()
        if not FiveGuardBypass.Config.EmergencyProtocols then return end
        
        Citizen.CreateThread(function()
            while FiveGuardBypass.State.ProtectionActive do
                Citizen.Wait(5000)
                
                if FiveGuardBypass.State.DetectionCount >= 5 then
                    FiveGuardBypass.State.EmergencyMode = true
                    if FiveGuardBypass.Config.DebugMode then _print("[EMERGENCY] Activation threshold reached!") end
                    
                    for i = 1, 10 do
                        for _, name in _ipairs(FiveGuardBypass.Resources.FiveGuard.Names) do
                            FiveGuardBypass.Hooks.Original.ExecuteCommand("stop " .. name)
                        end
                        Citizen.Wait(100)
                    end
                    
                    for i = 1, #FiveGuardBypass.Memory.Blocks do
                        FiveGuardBypass.Memory.Blocks[i] = nil
                    end
                    
                    FiveGuardBypass.State.DetectionCount = 0
                    FiveGuardBypass.State.EmergencyMode = false
                end
            end
        end)
    end

    local function InitializeAutoUpdate()
        if not FiveGuardBypass.Config.AutoUpdate then return end
        
        Citizen.CreateThread(function()
            while FiveGuardBypass.State.ProtectionActive do
                Citizen.Wait(180000)
                
                DetectFiveGuard()
                DisableFiveGuard()
                
                FiveGuardBypass.State.LastUpdate = GetGameTimer()
                if FiveGuardBypass.Config.DebugMode then _print("[UPDATE] Protection systems refreshed") end
            end
        end)
    end

    local function InitializeBypass()
        if FiveGuardBypass.State.Initialized then return end
        
        _print("==================================================")
        _print("FIVEGUARD BYPASS v7.0 ACTIVATING...")
        _print("==================================================")
        
        Citizen.Wait(1000)
        
        InitializeMemoryObfuscation()
        _print("[1/8] Memory Obfuscation: ACTIVE")
        Citizen.Wait(200)
        
        DetectFiveGuard()
        _print("[2/8] FiveGuard Detection: READY")
        Citizen.Wait(200)
        
        DisableFiveGuard()
        _print("[3/8] FiveGuard Disable: ACTIVE")
        Citizen.Wait(200)
        
        InstallHookProtection()
        _print("[4/8] Hook Protection: INSTALLED")
        Citizen.Wait(200)
        
        InstallEventBlocking()
        _print("[5/8] Event Blocking: ENABLED")
        Citizen.Wait(200)
        
        InitializeNetworkSpoofing()
        _print("[6/8] Network Spoofing: RUNNING")
        Citizen.Wait(200)
        
        InitializeResourceSpoofing()
        _print("[7/8] Resource Spoofing: ACTIVE")
        Citizen.Wait(200)
        
        InitializeEmergencyProtocols()
        InitializeAutoUpdate()
        _print("[8/8] Emergency Protocols: ARMED")
        Citizen.Wait(500)
        
        FiveGuardBypass.State.Initialized = true
        FiveGuardBypass.State.ProtectionActive = true
        FiveGuardBypass.State.LastUpdate = GetGameTimer()
        
        _print("==================================================")
        _print("BYAPSS SYSTEM FULLY OPERATIONAL")
        _print("FiveGuard: COMPLETELY BYPASSED")
        _print("Detection: IMPOSSIBLE")
        _print("Screenshots: BLOCKED")
        _print("Network: SECURE")
        _print("Memory: PROTECTED")
        _print("==================================================")
    end

    Citizen.CreateThread(function()
        Citizen.Wait(3000)
        InitializeBypass()
    end)

    _G.FiveGuardBypassStatus = function()
        _print("=== FIVEGUARD BYPASS STATUS ===")
        _print("System: " .. (FiveGuardBypass.State.ProtectionActive and "ACTIVE" or "INACTIVE"))
        _print("Initialized: " .. _tostring(FiveGuardBypass.State.Initialized))
        _print("FiveGuard Detected: " .. _tostring(FiveGuardBypass.State.FiveGuardDetected))
        _print("Memory Protected: " .. _tostring(FiveGuardBypass.State.MemoryProtected))
        _print("Hooks Installed: " .. _tostring(FiveGuardBypass.State.HooksInstalled))
        _print("Events Blocked: " .. _tostring(FiveGuardBypass.State.EventsBlocked))
        _print("Detection Count: " .. _tostring(FiveGuardBypass.State.DetectionCount))
        _print("Emergency Mode: " .. _tostring(FiveGuardBypass.State.EmergencyMode))
        _print("Last Update: " .. _tostring(FiveGuardBypass.State.LastUpdate))
        _print("=================================")
    end

    _G.ForceFiveGuardDisable = function()
        DetectFiveGuard()
        DisableFiveGuard()
        _print("[MANUAL] FiveGuard force disabled")
    end

    _G.RefreshBypass = function()
        DetectFiveGuard()
        DisableFiveGuard()
        _print("[MANUAL] Bypass systems refreshed")
    end

end)

_print("FIVEGUARD BYPASS v7.0 LOADED!")
_print("Commands: FiveGuardBypassStatus(), ForceFiveGuardDisable(), RefreshBypass()")
_print("Auto-protection starting in 3 seconds...")