# Defold websocket extension

[![Build Status](https://github.com/defold/extension-websocket/workflows/Build%20with%20bob/badge.svg)](https://github.com/defold/extension-websocket/actions)

## Installation
To use this library in your Defold project, add the following URL to your `game.project` dependencies:

https://github.com/defold/extension-websocket/archive/master.zip

We recommend using a link to a zip file of a [specific release](https://github.com/defold/extension-websocket/releases).

## API reference

https://defold.com/extension-websocket/api/

## Debugging

In order to make it easier to debug this extension, we provide a `game.project` setting `websocket.debug` (edit `game.project` as text and add):

```
[websocket]
debug = level
```

Set it to:

* `0` to disable debugging (i.e. no debug output).
* `1` to display state changes.
* `2` to display the messages sent and received.

## External resources

To verify that your websocket server works, you can test it with some tools.

* [websocat](https://github.com/vi/websocat)

Or, you can test your server on this web page:

* https://www.websocket.org/echo.html

To monitor all the packets sent to/from the client/server, you can use e.g.

* [Wireshark](https://www.wireshark.org)

For command line debugging, there's

* tcpdump: `sudo tcpdump -X -s0 -ilo0 port 8080 ` (example for local ws:// connection)

* tcpdump: `sudo tcpdump -X -s0 host echo.websocket.org` (Monitors packets to/from echo.websocket.org)

## Credits

This extension makes use of the C library WSlay by @tatsuhiro-t:

* https://github.com/tatsuhiro-t/wslay

The test server used by the example:

* https://www.lob.com/blog/websocket-org-is-down-here-is-an-alternative
