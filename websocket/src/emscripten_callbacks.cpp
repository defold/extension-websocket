#include "websocket.h"

#if defined(__EMSCRIPTEN__)

namespace dmWebsocket
{
EM_BOOL Emscripten_WebSocketOnOpen(int eventType, const EmscriptenWebSocketOpenEvent *websocketEvent, void *userData) {
    DebugLog(1, "WebSocket OnOpen");
    WebsocketConnection* conn = (WebsocketConnection*)userData;
    SetState(conn, STATE_CONNECTED);
    HandleCallback(conn, EVENT_CONNECTED, 0, 0);
    return EM_TRUE;
}
EM_BOOL Emscripten_WebSocketOnError(int eventType, const EmscriptenWebSocketErrorEvent *websocketEvent, void *userData) {
    DebugLog(1, "WebSocket OnError");
    WebsocketConnection* conn = (WebsocketConnection*)userData;
    conn->m_Status = RESULT_ERROR;
    SetState(conn, STATE_DISCONNECTED);
    return EM_TRUE;
}
EM_BOOL Emscripten_WebSocketOnClose(int eventType, const EmscriptenWebSocketCloseEvent *websocketEvent, void *userData) {
    DebugLog(1, "WebSocket OnClose");
    WebsocketConnection* conn = (WebsocketConnection*)userData;
    int length = strlen(websocketEvent->reason);
    PushMessage(conn, MESSAGE_TYPE_CLOSE, length, (uint8_t*)websocketEvent->reason, websocketEvent->code);
    return EM_TRUE;
}
EM_BOOL Emscripten_WebSocketOnMessage(int eventType, const EmscriptenWebSocketMessageEvent *websocketEvent, void *userData) {
    DebugLog(1, "WebSocket OnMessage");
    WebsocketConnection* conn = (WebsocketConnection*)userData;
    int length = websocketEvent->numBytes;
    if (websocketEvent->isText)
    {
        length--;
    }
    PushMessage(conn, MESSAGE_TYPE_NORMAL, length, websocketEvent->data, 0);
    return EM_TRUE;
}

} // namespace

#endif // __EMSCRIPTEN__
