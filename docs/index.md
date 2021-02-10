---
title: Defold websocket extension API documentation
brief: This manual covers how to use websockets with Defold
---

# Defold websocket extension API documentation

This extension supports both secure (`wss://`) and non secure (`ws://`) websocket connections.
All platforms should support this extension.


Here is how you connect to a websocket and listen to events:

```lua
local function websocket_callback(self, conn, data)
    if data.event == websocket.EVENT_DISCONNECTED then
        log("Disconnected: " .. tostring(conn))
        self.connection = nil
        update_gui(self)
    elseif data.event == websocket.EVENT_CONNECTED then
        update_gui(self)
        log("Connected: " .. tostring(conn))
    elseif data.event == websocket.EVENT_ERROR then
        log("Error: '" .. tostring(data.message) .. "'")
        if data.handshake_response then
            log("Handshake response status: '" .. tostring(data.handshake_response.status) .. "'")
            for key, value in pairs(data.handshake_response.headers) do
                log("Handshake response header: '" .. key .. ": " .. value .. "'")
            end
            log("Handshake response body: '" .. tostring(data.handshake_response.response) .. "'")
        end
    elseif data.event == websocket.EVENT_MESSAGE then
        log("Receiving: '" .. tostring(data.message) .. "'")
    end
end

function init(self)
    self.url = "ws://echo.websocket.org"
    local params = {}
    self.connection = websocket.connect(self.url, params, websocket_callback)
end

function finalize(self)
    if self.connection ~= nil then
        websocket.disconnect(self.connection)
    end
end
```


## Installation
To use this library in your Defold project, add the following URL to your `game.project` dependencies:

https://github.com/defold/extension-websocket/archive/master.zip

We recommend using a link to a zip file of a [specific release](https://github.com/defold/extension-websocket/releases).


## Source code

The source code is available on [GitHub](https://github.com/defold/extension-websocket)

## API reference

https://defold.com/extension-websocket/api/