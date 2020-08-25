// More info on websockets
//     https://tools.ietf.org/html/rfc6455

#define LIB_NAME "Websocket"
#define MODULE_NAME "websocket"

// include the Defold SDK
#include <dmsdk/sdk.h>

#include <wslay/wslay.h>

#include "connection_pool.h"
#include "socket.h"
#include "dns.h"
#include "uri.h"

#include "script_util.h"

extern "C" int mbedtls_base64_encode( unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen );
extern "C" int mbedtls_base64_decode( unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen );

namespace dmCrypt
{
    void HashSha1(const uint8_t* buf, uint32_t buflen, uint8_t* digest);
}

namespace dmWebsocket {

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
    char                            m_Key[16];
    wslay_event_context_ptr         m_Ctx;
    dmURI::Parts                    m_Url;
    dmConnectionPool::HConnection   m_Connection;
    dmSocket::Socket                m_Socket;
    State                           m_State;
    uint32_t                        m_SSL:1;
    char*                           m_Response;
    int                             m_ResponseSize;
    uint32_t                        m_ResponseCapacity;
    dmScript::LuaCallbackInfo*      m_Callback;
    Result                          m_Status;
};

struct WebsocketContext
{
    uint64_t                        m_BufferSize;
    int                             m_Timeout;
    dmArray<WebsocketConnection*>   m_Connections;
    dmConnectionPool::HPool         m_Pool;
    dmDNS::HChannel                 m_Channel;
    uint32_t                        m_Initialized:1;
} g_Websocket;


static void HandleCallback(WebsocketConnection* conn, int event, const uint8_t* msg, size_t msg_len);


#define WS_SENDALL(s) \
    sock_res = Send(conn, s, strlen(s), 0);\
    if (sock_res != dmSocket::RESULT_OK)\
    {\
        return sock_res;\
    }\

static void debugPrintBuffer(const char* s, size_t len)
{
            for (int i = 0; i < len; ++i)
            {
                const char* p = s + i;
                if (*p == '\r') {
                    printf("\\r");
                }
                else if (*p == '\n') {
                    printf("\\n\n");
                }
                else if (*p == '\t') {
                    printf("\t");
                }
                else {
                    printf("%c", *p);
                }
            }
}

static dmSocket::Result Send(WebsocketConnection* conn, const char* buffer, int length, int* out_sent_bytes)
{
    // if (response->m_SSLConnection != 0) {
    //     int r = 0;
    //     while( ( r = mbedtls_ssl_write(response->m_SSLConnection, (const uint8_t*) buffer, length) ) < 0 )
    //     {
    //         if (r == MBEDTLS_ERR_SSL_WANT_WRITE ||
    //             r == MBEDTLS_ERR_SSL_WANT_READ) {
    //             return dmSocket::RESULT_TRY_AGAIN;
    //         }

    //         if (r < 0) {
    //             return SSLToSocket(r);
    //         }
    //     }

    //     // In order to mimic the http code path, we return the same error number
    //     if( (r == length) && HasRequestTimedOut(response->m_Client) )
    //     {
    //         return dmSocket::RESULT_WOULDBLOCK;
    //     }

    //     if (r != length) {
    //         return SSLToSocket(r);
    //     }

    //     return dmSocket::RESULT_OK;
    // } else {
        int total_sent_bytes = 0;
        int sent_bytes = 0;

        while (total_sent_bytes < length) {

            dmSocket::Result r = dmSocket::Send(conn->m_Socket, buffer + total_sent_bytes, length - total_sent_bytes, &sent_bytes);

debugPrintBuffer(buffer + total_sent_bytes, sent_bytes);

            if( r == dmSocket::RESULT_WOULDBLOCK )
            {
                r = dmSocket::RESULT_TRY_AGAIN;
            }
            // if( (r == dmSocket::RESULT_OK || r == dmSocket::RESULT_TRY_AGAIN) && HasRequestTimedOut(response->m_Client) )
            // {
            //     r = dmSocket::RESULT_WOULDBLOCK;
            // }

            if (r == dmSocket::RESULT_TRY_AGAIN)
                continue;

            if (r != dmSocket::RESULT_OK) {
                return r;
            }

            total_sent_bytes += sent_bytes;
        }
        if (out_sent_bytes)
            *out_sent_bytes = total_sent_bytes;
        return dmSocket::RESULT_OK;
//    }
}

static dmSocket::Result Receive(WebsocketConnection* conn, void* buffer, int length, int* received_bytes)
{
    // if (response->m_SSLConnection != 0) {

    //     int ret = 0;
    //     do
    //     {
    //         memset(buffer, 0, length);
    //         ret = mbedtls_ssl_read( response->m_SSLConnection, (unsigned char*)buffer, length-1 );

    //         if( ret == MBEDTLS_ERR_SSL_WANT_READ ||
    //             ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
    //             ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS )
    //         {
    //             continue;
    //         }

    //         if (HasRequestTimedOut(response->m_Client)) {
    //             return dmSocket::RESULT_WOULDBLOCK;
    //         }

    //         if( ret <= 0 )
    //         {
    //             return SSLToSocket(ret);
    //         }

    //         ((uint8_t*)buffer)[ret] = 0;

    //         *received_bytes = ret;
    //         return dmSocket::RESULT_OK;
    //     }
    //     while( 1 );
    // } else {
        return dmSocket::Receive(conn->m_Socket, buffer, length, received_bytes);
    //}
}

static void CreateKey(char key[16])
{
    // TODO: Create proper key
    for (int i = 0; i < 16; ++i)
    {
        key[i] = (char)i;
    }
}

static void printHex(const uint8_t* data, size_t len)
{
    for (int i = 0; i < 16; ++i)
    {
        printf("%x", data[i]);
    }
}


static dmSocket::Result SendClientHandshake(WebsocketConnection* conn)
{
    printf("SendClientHandshake\n");

    CreateKey(conn->m_Key);
    printf("DBG: CreateKey: '");
    printHex((const uint8_t*)conn->m_Key, 16);
    printf("'\n");

    char encoded_key[32];
    size_t encoded_key_len = 0;
    mbedtls_base64_encode((unsigned char*)encoded_key, sizeof(encoded_key), &encoded_key_len, (const unsigned char*)conn->m_Key, sizeof(conn->m_Key));

    printf("DBG: encoded: '%s'\n", encoded_key);

    char port[8] = "";
    if (!(conn->m_Url.m_Port == 80 || conn->m_Url.m_Port == 443))
        dmSnPrintf(port, sizeof(port), ":%d", conn->m_Url.m_Port);

    dmSocket::Result sock_res = dmSocket::RESULT_OK;
    WS_SENDALL("GET /");
    WS_SENDALL(conn->m_Url.m_Path);
    WS_SENDALL(" HTTP/1.1\r\n");
    WS_SENDALL("Host: ");
    WS_SENDALL(conn->m_Url.m_Hostname);
    WS_SENDALL(port);
    WS_SENDALL("\r\n");
    WS_SENDALL("Upgrade: websocket\r\n");
    WS_SENDALL("Connection: Upgrade\r\n");
    WS_SENDALL("Sec-WebSocket-Key: ");
    WS_SENDALL(encoded_key);
    WS_SENDALL("\r\n");
    WS_SENDALL("Sec-WebSocket-Version: 13\r\n");

    // Add custom protocols

    // Add custom headers

    WS_SENDALL("\r\n");

    // String request = "GET " + p_path + " HTTP/1.1\r\n";
    // request += "Host: " + p_host + port + "\r\n";
    // request += "Upgrade: websocket\r\n";
    // request += "Connection: Upgrade\r\n";
    // request += "Sec-WebSocket-Key: " + _key + "\r\n";
    // request += "Sec-WebSocket-Version: 13\r\n";
    // if (p_protocols.size() > 0) {
    //     request += "Sec-WebSocket-Protocol: ";
    //     for (int i = 0; i < p_protocols.size(); i++) {
    //         if (i != 0) {
    //             request += ",";
    //         }
    //         request += p_protocols[i];
    //     }
    //     request += "\r\n";
    // }
    // for (int i = 0; i < p_custom_headers.size(); i++) {
    //     request += p_custom_headers[i] + "\r\n";
    // }
    // request += "\r\n";

    //dmSocket::SetNoDelay(conn->m_Socket, true);
    return sock_res;
}

static Result VerifyHeaders(WebsocketConnection* conn)
{
    char* r = conn->m_Response;

    printf("SERVER RESPONSE:\n%s\n", r);

    const char* http_version_and_status_protocol = "HTTP/1.1 101"; // optionally "Web Socket Protocol Handshake"
    if (strstr(r, http_version_and_status_protocol) != r) {
        dmLogError("Missing: '%s'", http_version_and_status_protocol);
        return RESULT_HANDSHAKE_FAILED;
    }
    r = strstr(r, "\r\n") + 2;


    bool upgraded = false;
    bool valid_key = false;
    const char* protocol = "";

    // Sec-WebSocket-Protocol

    // parse he
    while (r)
    {
        // Tokenize the each header line: "Key: Value\r\n"
        const char* key = r;
        r = strchr(r, ':');
        *r = 0;
        ++r;
        const char* value = r;
        while(*value == ' ')
            ++value;
        r = strstr(r, "\r\n");
        *r = 0;
        r += 2;

        printf("KEY: '%s', VALUE: '%s'\n", key, value);

        if (strcmp(key, "Connection") == 0 && strcmp(value, "Upgrade") == 0)
            upgraded = true;
        else if (strcmp(key, "Sec-WebSocket-Accept") == 0)
        {
            const char* magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // as per the rfc document on page 7 (https://tools.ietf.org/html/rfc6455)

            uint8_t client_key[64];
            size_t client_key_len = 0;
            mbedtls_base64_encode((unsigned char*)client_key, sizeof(client_key), &client_key_len, (const unsigned char*)conn->m_Key, sizeof(conn->m_Key));
            memcpy(client_key + client_key_len, magic, strlen(magic));
            client_key_len += strlen(magic);
            client_key[client_key_len] = 0;

            uint8_t client_key_sha1[20];
            dmCrypt::HashSha1(client_key, client_key_len, client_key_sha1);

            mbedtls_base64_encode((unsigned char*)client_key, sizeof(client_key), &client_key_len, client_key_sha1, sizeof(client_key_sha1));
            client_key[client_key_len] = 0;

            if (strcmp(value, (const char*)client_key) == 0)
                valid_key = true;

            printf("DBG: CLIENT KEY+MAGIC: '%s'\n", client_key);
        }

        if (strcmp(r, "\r\n") == 0)
            break;
    }

    return (upgraded && valid_key) ? RESULT_OK : RESULT_HANDSHAKE_FAILED;
}

static Result ReceiveHeaders(WebsocketConnection* conn)
{
    while (1)
    {
        int max_to_recv = (int)(g_Websocket.m_BufferSize - 1) - conn->m_ResponseSize; // allow for a terminating null character

        if (max_to_recv <= 0)
        {
            dmLogError("Receive buffer full");
            return RESULT_HANDSHAKE_FAILED;
        }

        int recv_bytes = 0;
        dmSocket::Result r = Receive(conn, conn->m_Response + conn->m_ResponseSize, max_to_recv, &recv_bytes);

        if( r == dmSocket::RESULT_WOULDBLOCK )
        {
            r = dmSocket::RESULT_TRY_AGAIN;
        }

        if (r == dmSocket::RESULT_TRY_AGAIN)
            continue;

        if (r != dmSocket::RESULT_OK)
        {
            dmLogError("Receive error: %s", dmSocket::ResultToString(r));
            return RESULT_HANDSHAKE_FAILED;
        }

debugPrintBuffer(conn->m_Response + conn->m_ResponseSize, recv_bytes);

        conn->m_ResponseSize += recv_bytes;

        // NOTE: We have an extra byte for null-termination so no buffer overrun here.
        conn->m_Response[conn->m_ResponseSize] = '\0';

        // Check if the end of the response has arrived
        if (conn->m_ResponseSize >= 4 && strcmp(conn->m_Response + conn->m_ResponseSize - 4, "\r\n\r\n") == 0)
        {
            return RESULT_OK;
        }

        if (r == 0)
        {
            dmLogError("Failed to parse headers:\n%s", conn->m_Response);
            return RESULT_HANDSHAKE_FAILED;
        }
    }
}

static ssize_t WSL_RecvCallback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *user_data)
{
    WebsocketConnection* conn = (WebsocketConnection*)user_data;

  // struct Session *session = (struct Session*)user_data;
  // ssize_t r;
  // while((r = recv(session->fd, buf, len, 0)) == -1 && errno == EINTR);
  // if(r == -1) {
  //   if(errno == EAGAIN || errno == EWOULDBLOCK) {
  //     wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
  //   } else {
  //     wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
  //   }
  // } else if(r == 0) {
  //   /* Unexpected EOF is also treated as an error */
  //   wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
  //   r = -1;
  // }
  // return r;

    int r = -1; // received bytes if >=0, error if < 0

    dmSocket::Result socket_result = Receive(conn, buf, len, &r);

    if (dmSocket::RESULT_OK == socket_result && r == 0)
        socket_result = dmSocket::RESULT_WOULDBLOCK;

    if (dmSocket::RESULT_OK != socket_result)
    {
        if (socket_result == dmSocket::RESULT_WOULDBLOCK || socket_result == dmSocket::RESULT_TRY_AGAIN) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        }
        else
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }
    return r;
}

static ssize_t WSL_SendCallback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data)
{
    WebsocketConnection* conn = (WebsocketConnection*)user_data;

    // struct Session *session = (struct Session*)user_data;
    // ssize_t r;

    // int sflags = 0;
    // // #ifdef MSG_MORE
    // //   if(flags & WSLAY_MSG_MORE) {
    // //     sflags |= MSG_MORE;
    // //   }
    // // #endif // MSG_MORE
    // while((r = send(session->fd, data, len, sflags)) == -1 && errno == EINTR);
    // if(r == -1) {
    //     if(errno == EAGAIN || errno == EWOULDBLOCK) {
    //         wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
    //     } else {
    //         wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    //     }
    // }
    // return r;

    int sent_bytes = 0;
    dmSocket::Result socket_result = Send(conn, (const char*)data, len, &sent_bytes);

    // dmSocket::Result socket_result;
    // int r = -1; // sent bytes if >=0, error if < 0

    // do {
    //     socket_result = dmSocket::Send(conn->m_Socket, data, len, &r);
    // }
    // while (r == -1 && socket_result == dmSocket::RESULT_INTR);

    if (socket_result != dmSocket::RESULT_OK)
    {
        if (socket_result == dmSocket::RESULT_WOULDBLOCK || socket_result == dmSocket::RESULT_TRY_AGAIN)
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        else
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }
    return (ssize_t)sent_bytes;
}

// Error WSLPeer::parse_message(const wslay_event_on_msg_recv_arg *arg) {
//     uint8_t is_string = 0;
//     if (arg->opcode == WSLAY_TEXT_FRAME) {
//         is_string = 1;
//     } else if (arg->opcode == WSLAY_CONNECTION_CLOSE) {
//         close_code = arg->status_code;
//         size_t len = arg->msg_length;
//         close_reason = "";
//         if (len > 2 /* first 2 bytes = close code */) {
//             close_reason.parse_utf8((char *)arg->msg + 2, len - 2);
//         }
//         if (!wslay_event_get_close_sent(_data->ctx)) {
//             if (_data->is_server) {
//                 WSLServer *helper = (WSLServer *)_data->obj;
//                 helper->_on_close_request(_data->id, close_code, close_reason);
//             } else {
//                 WSLClient *helper = (WSLClient *)_data->obj;
//                 helper->_on_close_request(close_code, close_reason);
//             }
//         }
//         return ERR_FILE_EOF;
//     } else if (arg->opcode != WSLAY_BINARY_FRAME) {
//         // Ping or pong
//         return ERR_SKIP;
//     }
//     _in_buffer.write_packet(arg->msg, arg->msg_length, &is_string);
//     return OK;
// }

static void WSL_OnMsgRecvCallback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg, void *user_data)
{
    WebsocketConnection* conn = (WebsocketConnection*)user_data;
    if (arg->opcode == WSLAY_TEXT_FRAME || arg->opcode == WSLAY_BINARY_FRAME)
    {
        HandleCallback(conn, EVENT_MESSAGE, arg->msg, arg->msg_length);
    } else if (arg->opcode == WSLAY_CONNECTION_CLOSE)
    {
        // TODO: Store the reason

        //         close_code = arg->status_code;
//         size_t len = arg->msg_length;
//         close_reason = "";
//         if (len > 2 /* first 2 bytes = close code */) {
//             close_reason.parse_utf8((char *)arg->msg + 2, len - 2);
//         }
//         if (!wslay_event_get_close_sent(_data->ctx)) {
//             if (_data->is_server) {
//                 WSLServer *helper = (WSLServer *)_data->obj;
//                 helper->_on_close_request(_data->id, close_code, close_reason);
//             } else {
//                 WSLClient *helper = (WSLClient *)_data->obj;
//                 helper->_on_close_request(close_code, close_reason);
//             }
//         }
    }
}

static int WSL_GenmaskCallback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data) {
    // RandomNumberGenerator rng;
    // // TODO maybe use crypto in the future?
    // rng.set_seed(OS::get_singleton()->get_unix_time());
    // for (unsigned int i = 0; i < len; i++) {
    //     buf[i] = (uint8_t)rng.randi_range(0, 255);
    // }
    // return 0;

    // TODO: Create a random mask
    for (unsigned int i = 0; i < len; i++) {
        buf[i] = (uint8_t)(i & 0xFF);
    }
    return 0;
}

// ***************************************************************************************************
// LUA functions

    // struct wslay_event_msg msg; // Should I use fragmented?
    // msg.opcode = write_mode == WRITE_MODE_TEXT ? WSLAY_TEXT_FRAME : WSLAY_BINARY_FRAME;
    // msg.msg = p_buffer;
    // msg.msg_length = p_buffer_size;

    // wslay_event_queue_msg(_data->ctx, &msg);
    // if (wslay_event_send(_data->ctx) < 0) {
    //     close_now();
    //     return FAILED;
    // }

const struct wslay_event_callbacks g_WslCallbacks = {
    WSL_RecvCallback,
    WSL_SendCallback,
    WSL_GenmaskCallback,
    NULL,
    NULL,
    NULL,
    WSL_OnMsgRecvCallback
};


static WebsocketConnection* WSL_CreateConnection()
{
    WebsocketConnection* conn = (WebsocketConnection*)malloc(sizeof(WebsocketConnection));
    memset(conn, 0, sizeof(WebsocketConnection));
    conn->m_ResponseCapacity = g_Websocket.m_BufferSize;
    conn->m_Response = (char*)malloc(conn->m_ResponseCapacity);
    return conn;
}

static void WSL_DestroyConnection(WebsocketConnection* conn)
{
    if (conn->m_State == STATE_CONNECTED)
        wslay_event_context_free(conn->m_Ctx);

    if (conn->m_Callback)
        dmScript::DestroyCallback(conn->m_Callback);

    if (conn->m_Connection)
        dmConnectionPool::Close(g_Websocket.m_Pool, conn->m_Connection);

    free((void*)conn->m_Response);
    free((void*)conn);
}

static void WSL_CloseConnection(WebsocketConnection* conn)
{
    // we want it to send this message in the polling
    if (conn->m_State == STATE_CONNECTED) {
        const char* reason = "Client wants to close";
        wslay_event_queue_close(conn->m_Ctx, 0, (const uint8_t*)reason, strlen(reason));
    }
    else
        conn->m_State = STATE_DISCONNECTED;
}


static Result WSL_OpenConnection(WebsocketConnection* conn, const char* url)
{
    dmURI::Parts uri;
    dmURI::Parse(url, &conn->m_Url);

    if (strcmp(conn->m_Url.m_Scheme, "https") == 0)
        strcpy(conn->m_Url.m_Scheme, "wss");

    conn->m_SSL = strcmp(conn->m_Url.m_Scheme, "wss") == 0 ? 1 : 0;

    conn->m_State = STATE_CONNECTING;
    // dmSocket::Result socket_result;
    // dmConnectionPool::Result pool_result = dmConnectionPool::Dial(g_Websocket.m_Pool, conn->m_Url.m_Hostname, conn->m_Url.m_Port, g_Websocket.m_Channel, conn->m_SSL, g_Websocket.m_Timeout, &conn->m_Connection, &socket_result);
    // if (dmConnectionPool::RESULT_OK != pool_result)
    // {
    //     return RESULT_NOT_CONNECTED;
    // }

    // conn->m_Socket = dmConnectionPool::GetSocket(g_Websocket.m_Pool, conn->m_Connection);

    // conn->m_State = STATE_HANDSHAKE;
    // socket_result = SendClientHandshake(conn);
    // if (dmSocket::RESULT_OK != socket_result)
    // {
    //     return RESULT_HANDSHAKE_FAILED;
    // }

    // Result result = ReceiveHeaders(conn);
    // if (RESULT_OK != result)
    // {
    //     dmLogError("Failed receiving Handshake headers");
    //     return result;
    // }

    // result = VerifyHeaders(conn);
    // if (RESULT_OK != result)
    // {
    //     dmLogError("Failed verifying handshake headers:\n%s\n\n", conn->m_Response);
    //     return result;
    // }

    // // Handshake complete, time to

    // // Currently only supports client implementation
    // int ret = -1;
    // ret = wslay_event_context_client_init(&conn->m_Ctx, &g_WslCallbacks, conn);
    // if (ret == 0)
    //     wslay_event_config_set_max_recv_msg_length(conn->m_Ctx, g_Websocket.m_BufferSize);
    // if (ret != 0)
    // {
    //     return RESULT_FAIL_WSLAY_INIT;
    // }

    // conn->m_State = STATE_CONNECTED;

    return RESULT_OK;
}

static int FindConnection(WebsocketConnection* conn)
{
    for (int i = 0; i < g_Websocket.m_Connections.Size(); ++i )
    {
        if (g_Websocket.m_Connections[i] == conn)
            return i;
    }
    return -1;
}

/*#
*
*/
static int WSL_Lua_Connect(lua_State* L)
{
    DM_LUA_STACK_CHECK(L, 2);

    if (!g_Websocket.m_Initialized)
        return DM_LUA_ERROR("The web socket module isn't initialized");

    const char* url = luaL_checkstring(L, 1);

    WebsocketConnection* conn = WSL_CreateConnection();
    Result result = WSL_OpenConnection(conn, url);
    if (RESULT_OK != result)
    {
        WSL_CloseConnection(conn);
        WSL_DestroyConnection(conn);

        char msg[256];

        switch (result)
        {
        case RESULT_FAIL_WSLAY_INIT:    dmSnPrintf(msg, sizeof(msg), "Failed to initialize websocket context for %s", url); break;
        case RESULT_NOT_CONNECTED:      dmSnPrintf(msg, sizeof(msg), "Failed to connect to %s", url); break;
        default:                        dmSnPrintf(msg, sizeof(msg), "Failed to create websocket for %s", url); break;
        }

        lua_pushnil(L);
        lua_pushstring(L, msg);
        return 2;
    }

    // long playedTime = luaL_checktable_number(L, 2, "playedTime", -1);
    // long progressValue = luaL_checktable_number(L, 2, "progressValue", -1);
    // char *description = luaL_checktable_string(L, 2, "description", NULL);
    // char *coverImage = luaL_checktable_string(L, 2, "coverImage", NULL);

    conn->m_Callback = dmScript::CreateCallback(L, 3);

    if (g_Websocket.m_Connections.Full())
        g_Websocket.m_Connections.OffsetCapacity(2);
    g_Websocket.m_Connections.Push(conn);

    lua_pushlightuserdata(L, conn);
    lua_pushnil(L);
    return 2;
}

static int WSL_Lua_Disconnect(lua_State* L)
{
    DM_LUA_STACK_CHECK(L, 0);

    if (!g_Websocket.m_Initialized)
        return DM_LUA_ERROR("The web socket module isn't initialized");

    if (!lua_islightuserdata(L, 1))
        return DM_LUA_ERROR("The first argument must be a valid connection!");

    WebsocketConnection* conn = (WebsocketConnection*)lua_touserdata(L, 1);

    int i = FindConnection(conn);
    if (i != -1)
    {
        WSL_CloseConnection(conn);
    }
    return 0;
}

static int WSL_Lua_Send(lua_State* L)
{
    DM_LUA_STACK_CHECK(L, 0);

    if (!g_Websocket.m_Initialized)
        return DM_LUA_ERROR("The web socket module isn't initialized");

    if (!lua_islightuserdata(L, 1))
        return DM_LUA_ERROR("The first argument must be a valid connection!");

    WebsocketConnection* conn = (WebsocketConnection*)lua_touserdata(L, 1);

    int i = FindConnection(conn);
    if (i == -1)
        return DM_LUA_ERROR("Invalid connection");

    if (conn->m_State != STATE_CONNECTED)
        return DM_LUA_ERROR("Connection isn't connected");

    size_t string_length = 0;
    const char* string = luaL_checklstring(L, 2, &string_length);

    int write_mode = WSLAY_BINARY_FRAME; // WSLAY_TEXT_FRAME

    struct wslay_event_msg msg;
    msg.opcode = write_mode;
    msg.msg = (const uint8_t*)string;
    msg.msg_length = string_length;

    wslay_event_queue_msg(conn->m_Ctx, &msg); // it makes a copy of the data

    return 0;
}

static void HandleCallback(WebsocketConnection* conn, int event, const uint8_t* msg, size_t msg_len)
{
    if (!dmScript::IsCallbackValid(conn->m_Callback))
        return;

    lua_State* L = dmScript::GetCallbackLuaContext(conn->m_Callback);
    DM_LUA_STACK_CHECK(L, 0)

    if (!dmScript::SetupCallback(conn->m_Callback))
    {
        dmLogError("Failed to setup callback");
        return;
    }

    lua_pushlightuserdata(L, conn);

    lua_newtable(L);

    lua_pushinteger(L, event);
    lua_setfield(L, -2, "event");

    lua_pushinteger(L, conn->m_Status);
    lua_setfield(L, -2, "status");

    if (conn->m_Status != RESULT_OK)
    {
        //lua_pushstring(L, conn->m_ErrorMessage);
        lua_pushstring(L, "TODO: Some error");
        lua_setfield(L, -2, "error");
    }

    if (msg != 0) {
        lua_pushlstring(L, (const char*)msg, msg_len);
        lua_setfield(L, -2, "message");
    }

    dmScript::PCall(L, 3, 0);

    dmScript::TeardownCallback(conn->m_Callback);
}

#define WSLAY_CASE(_X) case _X: return #_X;

static const char* WSL_ResultToString(int err)
{
    switch(err) {
        WSLAY_CASE(WSLAY_ERR_WANT_READ);
        WSLAY_CASE(WSLAY_ERR_WANT_WRITE);
        WSLAY_CASE(WSLAY_ERR_PROTO);
        WSLAY_CASE(WSLAY_ERR_INVALID_ARGUMENT);
        WSLAY_CASE(WSLAY_ERR_INVALID_CALLBACK);
        WSLAY_CASE(WSLAY_ERR_NO_MORE_MSG);
        WSLAY_CASE(WSLAY_ERR_CALLBACK_FAILURE);
        WSLAY_CASE(WSLAY_ERR_WOULDBLOCK);
        WSLAY_CASE(WSLAY_ERR_NOMEM);
        default: return "Unknown error";
    };
}

#undef WSLAY_CASE

// ***************************************************************************************************
// Life cycle functions

// Functions exposed to Lua
static const luaL_reg Websocket_module_methods[] =
{
    {"connect", WSL_Lua_Connect},
    {"disconnect", WSL_Lua_Disconnect},
    {"send", WSL_Lua_Send},
    {0, 0}
};

static void LuaInit(lua_State* L)
{
    int top = lua_gettop(L);

    // Register lua names
    luaL_register(L, MODULE_NAME, Websocket_module_methods);

#define SETCONSTANT(name, val) \
            lua_pushnumber(L, (lua_Number) val); \
            lua_setfield(L, -2, #name);

        SETCONSTANT(EVENT_CONNECTED, EVENT_CONNECTED);
        SETCONSTANT(EVENT_DISCONNECTED, EVENT_DISCONNECTED);
        SETCONSTANT(EVENT_MESSAGE, EVENT_MESSAGE);

#undef SETCONSTANT

    lua_pop(L, 1);
    assert(top == lua_gettop(L));
}

static dmExtension::Result WebsocketAppInitialize(dmExtension::AppParams* params)
{
    g_Websocket.m_BufferSize = dmConfigFile::GetInt(params->m_ConfigFile, "websocket.buffer_size", 64 * 1024);
    g_Websocket.m_Timeout = dmConfigFile::GetInt(params->m_ConfigFile, "websocket.socket_timeout", 250 * 1000);
    g_Websocket.m_Connections.SetCapacity(4);
    g_Websocket.m_Channel = 0;
    g_Websocket.m_Pool = 0;

    dmConnectionPool::Params pool_params;
    pool_params.m_MaxConnections = dmConfigFile::GetInt(params->m_ConfigFile, "websocket.max_connections", 2);
    dmConnectionPool::Result result = dmConnectionPool::New(&pool_params, &g_Websocket.m_Pool);

    if (dmConnectionPool::RESULT_OK != result)
    {
        dmLogError("Failed to create connection pool: %d", result);
    }

    dmDNS::Result dns_result = dmDNS::NewChannel(&g_Websocket.m_Channel);

    if (dmDNS::RESULT_OK != dns_result)
    {
        dmLogError("Failed to create connection pool: %s", dmDNS::ResultToString(dns_result));
    }

    g_Websocket.m_Initialized = 1;
    if (g_Websocket.m_Channel == 0 || g_Websocket.m_Pool == 0)
    {
        if (g_Websocket.m_Channel)
            dmDNS::DeleteChannel(g_Websocket.m_Channel);
        if (g_Websocket.m_Pool)
            dmConnectionPool::Delete(g_Websocket.m_Pool);

        g_Websocket.m_Initialized = 0;
    }

    return dmExtension::RESULT_OK;
}

static dmExtension::Result WebsocketInitialize(dmExtension::Params* params)
{
    if (!g_Websocket.m_Initialized)
        return dmExtension::RESULT_OK;

    LuaInit(params->m_L);
    dmLogInfo("Registered %s extension\n", MODULE_NAME);

    return dmExtension::RESULT_OK;
}

static dmExtension::Result WebsocketAppFinalize(dmExtension::AppParams* params)
{
    return dmExtension::RESULT_OK;
}

static dmExtension::Result WebsocketFinalize(dmExtension::Params* params)
{
    return dmExtension::RESULT_OK;
}

static dmExtension::Result WebsocketOnUpdate(dmExtension::Params* params)
{
    uint32_t size = g_Websocket.m_Connections.Size();

#define CLOSE_CONN(MSG, ...) \
    dmLogError(MSG, __VA_ARGS__); \
    WSL_CloseConnection(conn);

    for (uint32_t i = 0; i < size; ++i)
    {
        WebsocketConnection* conn = g_Websocket.m_Connections[i];

        if (STATE_DISCONNECTED == conn->m_State)
        {
            HandleCallback(conn, EVENT_DISCONNECTED, 0, 0);

            g_Websocket.m_Connections.EraseSwap(i);
            --i;
            --size;
            WSL_DestroyConnection(conn);
        }
        else if (STATE_CONNECTED == conn->m_State)
        {
            int err = 0;
            if ((err = wslay_event_recv(conn->m_Ctx)) != 0 || (err = wslay_event_send(conn->m_Ctx)) != 0) {
                dmLogError("Websocket poll error: %s from %s", WSL_ResultToString(err), conn->m_Url.m_Hostname);
            }

            if ((wslay_event_get_close_sent(conn->m_Ctx) && wslay_event_get_close_received(conn->m_Ctx))) {
                CLOSE_CONN("Websocket received close event for %s", conn->m_Url.m_Hostname);
                conn->m_State = STATE_DISCONNECTED;
                continue;
            }
        }
        else if (STATE_HANDSHAKE == conn->m_State)
        {
            // TODO: Split up this state into three?
            // e.g. STATE_HANDSHAKE_SEND, STATE_HANDSHAKE_RECEIVE, STATE_HANDSHAKE_VERIFY

            dmSocket::Result socket_result = SendClientHandshake(conn);
            if (dmSocket::RESULT_OK != socket_result)
            {
                CLOSE_CONN("Failed sending handshake: %s", dmSocket::ResultToString(socket_result));
                continue;
            }

            Result result = ReceiveHeaders(conn);
            if (RESULT_OK != result)
            {
                CLOSE_CONN("Failed receiving handshake headers. %d", result);
                continue;
            }

            result = VerifyHeaders(conn);
            if (RESULT_OK != result)
            {
                CLOSE_CONN("Failed verifying handshake headers:\n%s\n\n", conn->m_Response);
                continue;
            }

            // Currently only supports client implementation
            int ret = -1;
            ret = wslay_event_context_client_init(&conn->m_Ctx, &g_WslCallbacks, conn);
            if (ret == 0)
                wslay_event_config_set_max_recv_msg_length(conn->m_Ctx, g_Websocket.m_BufferSize);
            if (ret != 0)
            {
                CLOSE_CONN("Failed initializing wslay: %s", WSL_ResultToString(ret));
                continue;
            }

            if (conn->m_Socket) {
                dmSocket::SetNoDelay(conn->m_Socket, true);
                dmSocket::SetBlocking(conn->m_Socket, false);
                dmSocket::SetReceiveTimeout(conn->m_Socket, 500);
            }

            conn->m_Response[0] = 0;
            conn->m_ResponseSize = 0;
            conn->m_State = STATE_CONNECTED;

            HandleCallback(conn, EVENT_CONNECTED, 0, 0);
        }
        else if (STATE_CONNECTING == conn->m_State)
        {
            // wait for it to finish
            dmSocket::Result socket_result;
            dmConnectionPool::Result pool_result = dmConnectionPool::Dial(g_Websocket.m_Pool, conn->m_Url.m_Hostname, conn->m_Url.m_Port, g_Websocket.m_Channel, conn->m_SSL, g_Websocket.m_Timeout, &conn->m_Connection, &socket_result);
            if (dmConnectionPool::RESULT_OK != pool_result)
            {
                CLOSE_CONN("Failed to open connection: %s", dmSocket::ResultToString(socket_result));
                continue;
            }

            conn->m_Socket = dmConnectionPool::GetSocket(g_Websocket.m_Pool, conn->m_Connection);
            conn->m_State = STATE_HANDSHAKE;
        }
    }

    return dmExtension::RESULT_OK;
}

} // dmWebsocket

DM_DECLARE_EXTENSION(Websocket, LIB_NAME, dmWebsocket::WebsocketAppInitialize, dmWebsocket::WebsocketAppFinalize, dmWebsocket::WebsocketInitialize, dmWebsocket::WebsocketOnUpdate, 0, dmWebsocket::WebsocketFinalize)

