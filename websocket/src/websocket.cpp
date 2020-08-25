// More info on websockets
//     https://tools.ietf.org/html/rfc6455

#define LIB_NAME "Websocket"
#define MODULE_NAME "websocket"

#include "websocket.h"


#include "script_util.h"


// *****************************************************************************************************************************************************************
// DMSDK

extern "C" int mbedtls_base64_encode( unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen );
extern "C" int mbedtls_base64_decode( unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen );

// TODO: MOVE TO DMSDK
bool dmCrypt::Base64Encode(const uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t* dst_len)
{
    size_t out_len = 0;
    int r = mbedtls_base64_encode(dst, *dst_len, &out_len, src, src_len);
    if (r != 0)
    {
        *dst_len = 0xFFFFFFFF;
        return false;
    }
    *dst_len = (uint32_t)out_len;
    return true;
}

bool dmCrypt::Base64Decode(const uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t* dst_len)
{
    size_t out_len = 0;
    int r = mbedtls_base64_decode(dst, *dst_len, &out_len, src, src_len);
    if (r != 0)
    {
        *dst_len = 0xFFFFFFFF;
        return false;
    }
    *dst_len = (uint32_t)out_len;
    return true;
}

// *****************************************************************************************************************************************************************

namespace dmWebsocket {


struct WebsocketContext
{
    uint64_t                        m_BufferSize;
    int                             m_Timeout;
    dmArray<WebsocketConnection*>   m_Connections;
    dmConnectionPool::HPool         m_Pool;
    dmDNS::HChannel                 m_Channel;
    uint32_t                        m_Initialized:1;
} g_Websocket;


Result SetStatus(WebsocketConnection* conn, Result status, const char* format, ...)
{
    if (conn->m_Status == RESULT_OK)
    {
        va_list lst;
        va_start(lst, format);

        conn->m_BufferSize = vsnprintf(conn->m_Buffer, conn->m_BufferCapacity, format, lst);
        va_end(lst);
        conn->m_Status = status;
    }
    return status;
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


static WebsocketConnection* CreateConnection(const char* url)
{
    WebsocketConnection* conn = (WebsocketConnection*)malloc(sizeof(WebsocketConnection));
    memset(conn, 0, sizeof(WebsocketConnection));
    conn->m_BufferCapacity = g_Websocket.m_BufferSize;
    conn->m_Buffer = (char*)malloc(conn->m_BufferCapacity);

    dmURI::Parts uri;
    dmURI::Parse(url, &conn->m_Url);

    if (strcmp(conn->m_Url.m_Scheme, "https") == 0)
        strcpy(conn->m_Url.m_Scheme, "wss");

    conn->m_SSL = strcmp(conn->m_Url.m_Scheme, "wss") == 0 ? 1 : 0;
    conn->m_State = STATE_CONNECTING;

    return conn;
}

static void DestroyConnection(WebsocketConnection* conn)
{
    if (conn->m_State == STATE_CONNECTED)
        wslay_event_context_free(conn->m_Ctx);

    if (conn->m_Callback)
        dmScript::DestroyCallback(conn->m_Callback);

    if (conn->m_Connection)
        dmConnectionPool::Close(g_Websocket.m_Pool, conn->m_Connection);

    free((void*)conn->m_Buffer);
    free((void*)conn);
}

static void CloseConnection(WebsocketConnection* conn)
{
    // we want it to send this message in the polling
    if (conn->m_State == STATE_CONNECTED) {
        const char* reason = "Client wants to close";
        wslay_event_queue_close(conn->m_Ctx, 0, (const uint8_t*)reason, strlen(reason));
    }
    else
        conn->m_State = STATE_DISCONNECTED;
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
static int LuaConnect(lua_State* L)
{
    DM_LUA_STACK_CHECK(L, 1);

    if (!g_Websocket.m_Initialized)
        return DM_LUA_ERROR("The web socket module isn't initialized");

    const char* url = luaL_checkstring(L, 1);

    // long playedTime = luaL_checktable_number(L, 2, "playedTime", -1);
    // long progressValue = luaL_checktable_number(L, 2, "progressValue", -1);
    // char *description = luaL_checktable_string(L, 2, "description", NULL);
    // char *coverImage = luaL_checktable_string(L, 2, "coverImage", NULL);

    WebsocketConnection* conn = CreateConnection(url);

    conn->m_Callback = dmScript::CreateCallback(L, 3);

    if (g_Websocket.m_Connections.Full())
        g_Websocket.m_Connections.OffsetCapacity(2);
    g_Websocket.m_Connections.Push(conn);

    lua_pushlightuserdata(L, conn);
    return 1;
}

static int LuaDisconnect(lua_State* L)
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
        CloseConnection(conn);
    }
    return 0;
}

static int LuaSend(lua_State* L)
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
        lua_pushstring(L, conn->m_Buffer);
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
    {"connect", LuaConnect},
    {"disconnect", LuaDisconnect},
    {"send", LuaSend},
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
    CloseConnection(conn);

    for (uint32_t i = 0; i < size; ++i)
    {
        WebsocketConnection* conn = g_Websocket.m_Connections[i];

        if (STATE_DISCONNECTED == conn->m_State)
        {
            HandleCallback(conn, EVENT_DISCONNECTED, 0, 0);

            g_Websocket.m_Connections.EraseSwap(i);
            --i;
            --size;
            DestroyConnection(conn);
        }
        else if (STATE_CONNECTED == conn->m_State)
        {
            // Do we need to loop here?
            int err = 0;
            if ((err = wslay_event_recv(conn->m_Ctx)) != 0 || (err = wslay_event_send(conn->m_Ctx)) != 0) {
                dmLogError("Websocket poll error: %s from %s", WSL_ResultToString(err), conn->m_Url.m_Hostname);
            }

            if ((wslay_event_get_close_sent(conn->m_Ctx) && wslay_event_get_close_received(conn->m_Ctx))) {
                CLOSE_CONN("Websocket received close event for %s", conn->m_Url.m_Hostname);
                conn->m_State = STATE_DISCONNECTED;
                continue;
            }

            if (conn->m_HasMessage)
            {
                HandleCallback(conn, EVENT_MESSAGE, (uint8_t*)conn->m_Buffer, conn->m_BufferSize);
                conn->m_HasMessage = 0;
            }
        }
        else if (STATE_HANDSHAKE == conn->m_State)
        {
            // TODO: Split up this state into three?
            // e.g. STATE_HANDSHAKE_SEND, STATE_HANDSHAKE_RECEIVE, STATE_HANDSHAKE_VERIFY

            Result result = SendClientHandshake(conn);
            if (RESULT_OK != result)
            {
                CLOSE_CONN("Failed sending handshake: %d", result);
                continue;
            }

            result = ReceiveHeaders(conn);
            if (RESULT_OK != result)
            {
                CLOSE_CONN("Failed receiving handshake headers. %d", result);
                continue;
            }

            result = VerifyHeaders(conn);
            if (RESULT_OK != result)
            {
                CLOSE_CONN("Failed verifying handshake headers:\n%s\n\n", conn->m_Buffer);
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
                SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Failed initializing wslay: %s", WSL_ResultToString(ret));
                continue;
            }

            if (conn->m_Socket) {
                dmSocket::SetNoDelay(conn->m_Socket, true);
                dmSocket::SetBlocking(conn->m_Socket, false);
                dmSocket::SetReceiveTimeout(conn->m_Socket, 500);
            }

            conn->m_Buffer[0] = 0;
            conn->m_BufferSize = 0;
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

