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
        print("disconnected " .. conn)
        self.connection = nil
    elseif data.event == websocket.EVENT_CONNECTED then
        print("Connected " .. conn)
        -- self.connection = conn
    elseif data.event == websocket.EVENT_ERROR then
        print("Error:", data.error)
    elseif data.event == websocket.EVENT_MESSAGE then
        print("Receiving: '" .. tostring(data.message) .. "'")
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