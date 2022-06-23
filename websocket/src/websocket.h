#pragma once

#if defined(_WIN32)
#include <WinSock2.h>
#endif

// include the Defold SDK
#include <dmsdk/sdk.h>

#if !defined(__EMSCRIPTEN__)
    #define HAVE_WSLAY 1
#endif

#if defined(HAVE_WSLAY)
    #include <wslay/wslay.h>
    #endif

#if defined(__EMSCRIPTEN__)
#include "emscripten/websocket.h"
#endif

#include <dmsdk/dlib/connection_pool.h>
#include <dmsdk/dlib/socket.h>
#include <dmsdk/dlib/uri.h>
#include <dmsdk/dlib/array.h>
#include <dmsdk/dlib/thread.h>

namespace dmCrypt
{
    void HashSha1(const uint8_t* buf, uint32_t buflen, uint8_t* digest);
    bool Base64Encode(const uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t* dst_len);
    bool Base64Decode(const uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t* dst_len);
}

namespace dmWebsocket
{
    // Maximum time to wait for a socket
    static const int SOCKET_WAIT_TIMEOUT = 4*1000;

    enum State
    {
        STATE_CREATE,
        STATE_CONNECTING,
        STATE_HANDSHAKE_WRITE,
        STATE_HANDSHAKE_READ,
        STATE_CONNECTED,
        STATE_DISCONNECTING,
        STATE_DISCONNECTED,
    };

    enum Result
    {
        RESULT_OK,
        RESULT_ERROR,
        RESULT_FAIL_WSLAY_INIT,
        RESULT_NOT_CONNECTED,
        RESULT_HANDSHAKE_FAILED,
        RESULT_WOULDBLOCK,
    };

    enum Event
    {
        EVENT_CONNECTED,
        EVENT_DISCONNECTED,
        EVENT_MESSAGE,
        EVENT_ERROR,
    };

    enum MessageType
    {
        MESSAGE_TYPE_NORMAL = 0,
        MESSAGE_TYPE_CLOSE  = 1,
    };

    enum DataType
    {
        DATA_TYPE_BINARY = 0,
        DATA_TYPE_TEXT   = 1,
    };

    struct Message
    {
        uint16_t m_Code;
        uint32_t m_Length:30;
        uint32_t m_Type:2;
    };

    struct HttpHeader
    {
        const char* m_Key;
        const char* m_Value;
        HttpHeader(const char* key, const char* value);
        ~HttpHeader();
    };

    struct HandshakeResponse
    {
        int m_HttpMajor;
        int m_HttpMinor;
        int m_ResponseStatusCode;
        int m_BodyOffset;
        dmArray<HttpHeader*> m_Headers;

        ~HandshakeResponse();
        HttpHeader* GetHeader(const char* header);
    };


    struct WebsocketConnection
    {
        dmScript::LuaCallbackInfo*      m_Callback;
#if defined(HAVE_WSLAY)
        wslay_event_context_ptr         m_Ctx;
#endif
#if defined(__EMSCRIPTEN__)
        EMSCRIPTEN_WEBSOCKET_T          m_WS;
#endif
        dmURI::Parts                    m_Url;
        dmConnectionPool::HConnection   m_Connection;
        dmSocket::Socket                m_Socket;
        dmSSLSocket::Socket             m_SSLSocket;
        dmThread::Thread                m_ConnectionThread;
        dmArray<Message>                m_Messages; // lengths of the messages in the data buffer
        uint64_t                        m_ConnectTimeout;
        uint8_t                         m_Key[16];
        const char*                     m_Protocol;
        const char*                     m_CustomHeaders;
        State                           m_State;
        char*                           m_Buffer;
        int                             m_BufferSize;
        uint32_t                        m_BufferCapacity;
        Result                          m_Status;
        uint16_t                        m_CloseCode;
        uint8_t                         m_SSL:1;
        uint8_t                         m_HasHandshakeData:1;
        uint8_t                         :7;
        HandshakeResponse*              m_HandshakeResponse;
    };

    // Set error message
#ifdef __GNUC__
    Result SetStatus(WebsocketConnection* conn, Result status, const char* fmt, ...) __attribute__ ((format (printf, 3, 4)));
#else
    Result SetStatus(WebsocketConnection* conn, Result status, const char* fmt, ...);
#endif

    // Set socket state
    void SetState(WebsocketConnection* conn, State state);

    // Communication
    dmSocket::Result Send(WebsocketConnection* conn, const char* buffer, int length, int* out_sent_bytes);
    dmSocket::Result Receive(WebsocketConnection* conn, void* buffer, int length, int* received_bytes);
    dmSocket::Result WaitForSocket(WebsocketConnection* conn, dmSocket::SelectorKind kind, int timeout);

    // Handshake
    Result SendClientHandshake(WebsocketConnection* conn);
    Result ReceiveHeaders(WebsocketConnection* conn);
    Result VerifyHeaders(WebsocketConnection* conn);

    // Callback to Lua
    void HandleCallback(WebsocketConnection* conn, int event, int msg_offset, int msg_length);

    // Messages
    Result PushMessage(WebsocketConnection* conn, MessageType type, int length, const uint8_t* msg, uint16_t code);

#if defined(HAVE_WSLAY)
    // Wslay callbacks
    int     WSL_Init(wslay_event_context_ptr* ctx, ssize_t buffer_size, void* userctx);
    void    WSL_Exit(wslay_event_context_ptr ctx);
    int     WSL_Close(wslay_event_context_ptr ctx);
    int     WSL_Poll(wslay_event_context_ptr ctx);
    ssize_t WSL_RecvCallback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *user_data);
    ssize_t WSL_SendCallback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data);
    void    WSL_OnMsgRecvCallback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg, void *user_data);
    int     WSL_GenmaskCallback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data);
    const char* WSL_ResultToString(int err);
#endif
#if defined(__EMSCRIPTEN__)
    EM_BOOL Emscripten_WebSocketOnOpen(int eventType, const EmscriptenWebSocketOpenEvent *websocketEvent, void *userData);
    EM_BOOL Emscripten_WebSocketOnError(int eventType, const EmscriptenWebSocketErrorEvent *websocketEvent, void *userData);
    EM_BOOL Emscripten_WebSocketOnClose(int eventType, const EmscriptenWebSocketCloseEvent *websocketEvent, void *userData);
    EM_BOOL Emscripten_WebSocketOnMessage(int eventType, const EmscriptenWebSocketMessageEvent *websocketEvent, void *userData);
#endif

    // Random numbers (PCG)
    typedef struct { uint64_t state;  uint64_t inc; } pcg32_random_t;
    void pcg32_srandom_r(pcg32_random_t* rng, uint64_t initstate, uint64_t initseq);
    uint32_t pcg32_random_r(pcg32_random_t* rng);

    // If level <= dmWebSocket::g_DebugWebSocket, then it outputs the message
#ifdef __GNUC__
    void DebugLog(int level, const char* fmt, ...) __attribute__ ((format (printf, 2, 3)));
#else
    void DebugLog(int level, const char* fmt, ...);
#endif
    void DebugPrint(int level, const char* msg, const void* _bytes, uint32_t num_bytes);
}
