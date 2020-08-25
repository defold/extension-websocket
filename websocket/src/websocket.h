#pragma once

// include the Defold SDK
#include <dmsdk/sdk.h>

#include <wslay/wslay.h>

#include "dmsdk/connection_pool.h"
#include "dmsdk/socket.h"
#include "dmsdk/dns.h"
#include "dmsdk/uri.h"

namespace dmCrypt
{
    void HashSha1(const uint8_t* buf, uint32_t buflen, uint8_t* digest);
    bool Base64Encode(const uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t* dst_len);
    bool Base64Decode(const uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t* dst_len);
}

namespace dmWebsocket
{
    enum State
    {
        STATE_CONNECTING,
        STATE_HANDSHAKE,
        STATE_CONNECTED,
        STATE_DISCONNECTED,
    };

    enum Result
    {
        RESULT_OK,
        RESULT_FAIL_WSLAY_INIT,
        RESULT_NOT_CONNECTED,
        RESULT_HANDSHAKE_FAILED,
    };

    enum Event
    {
        EVENT_CONNECTED,
        EVENT_DISCONNECTED,
        EVENT_MESSAGE,
    };

    struct WebsocketConnection
    {
        dmScript::LuaCallbackInfo*      m_Callback;
        wslay_event_context_ptr         m_Ctx;
        dmURI::Parts                    m_Url;
        dmConnectionPool::HConnection   m_Connection;
        dmSocket::Socket                m_Socket;
        uint8_t                         m_Key[16];
        State                           m_State;
        uint32_t                        m_SSL:1;
        uint32_t                        m_HasMessage:1;
        char*                           m_Buffer;
        int                             m_BufferSize;
        uint32_t                        m_BufferCapacity;
        Result                          m_Status;
    };

    // Set error message
#ifdef __GNUC__
    Result SetStatus(WebsocketConnection* conn, Result status, const char* fmt, ...) __attribute__ ((format (printf, 3, 4)));
#else
    Result SetStatus(WebsocketCOnnection* conn, Result status, const char* fmt, ...);
#endif

    // Communication
    dmSocket::Result Send(WebsocketConnection* conn, const char* buffer, int length, int* out_sent_bytes);
    dmSocket::Result Receive(WebsocketConnection* conn, void* buffer, int length, int* received_bytes);

    // Handshake
    Result SendClientHandshake(WebsocketConnection* conn);
    Result ReceiveHeaders(WebsocketConnection* conn);
    Result VerifyHeaders(WebsocketConnection* conn);

    // Wslay callbacks
    ssize_t WSL_RecvCallback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *user_data);
    ssize_t WSL_SendCallback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data);
    void    WSL_OnMsgRecvCallback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg, void *user_data);
    int     WSL_GenmaskCallback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data);

    // Random numbers (PCG)
    typedef struct { uint64_t state;  uint64_t inc; } pcg32_random_t;
    void pcg32_srandom_r(pcg32_random_t* rng, uint64_t initstate, uint64_t initseq);
    uint32_t pcg32_random_r(pcg32_random_t* rng);
}











