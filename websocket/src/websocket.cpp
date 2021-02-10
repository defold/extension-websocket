// More info on websockets
//     https://tools.ietf.org/html/rfc6455

#define LIB_NAME "Websocket"
#define MODULE_NAME "websocket"

#include "websocket.h"
#include "script_util.h"
#include <dmsdk/dlib/connection_pool.h>
#include <dmsdk/dlib/dns.h>
#include <dmsdk/dlib/sslsocket.h>
#include <ctype.h> // isprint et al

#if defined(__EMSCRIPTEN__)
#include <emscripten/emscripten.h> // for EM_ASM
#endif

#if defined(WIN32)
#include <malloc.h>
#define alloca _alloca
#endif

namespace dmWebsocket {

int g_DebugWebSocket = 0;

struct WebsocketContext
{
    uint64_t                        m_BufferSize;
    int                             m_Timeout;
    dmArray<WebsocketConnection*>   m_Connections;
    dmConnectionPool::HPool         m_Pool;
    dmDNS::HChannel                 m_Channel;
    uint32_t                        m_Initialized:1;
} g_Websocket;


#define STRING_CASE(_X) case _X: return #_X;

const char* ResultToString(Result err)
{
    switch(err) {
        STRING_CASE(RESULT_OK);
        STRING_CASE(RESULT_ERROR);
        STRING_CASE(RESULT_FAIL_WSLAY_INIT);
        STRING_CASE(RESULT_NOT_CONNECTED);
        STRING_CASE(RESULT_HANDSHAKE_FAILED);
        STRING_CASE(RESULT_WOULDBLOCK);
        default: return "Unknown result";
    };
}

const char* StateToString(State err)
{
    switch(err) {
        STRING_CASE(STATE_CONNECTING);
        STRING_CASE(STATE_HANDSHAKE_WRITE);
        STRING_CASE(STATE_HANDSHAKE_READ);
        STRING_CASE(STATE_CONNECTED);
        STRING_CASE(STATE_DISCONNECTED);
        default: return "Unknown error";
    };
}

#undef STRING_CASE

void DebugLog(int level, const char* fmt, ...)
{
    if (level > g_DebugWebSocket)
        return;

    size_t buffer_size = 4096;
    char* buffer = (char*)alloca(buffer_size);
    va_list lst;
    va_start(lst, fmt);

    buffer_size = vsnprintf(buffer, buffer_size, fmt, lst);
    dmLogWarning("%s", buffer);
    va_end(lst);
}

void DebugPrint(int level, const char* msg, const void* _bytes, uint32_t num_bytes)
{
    if (level > g_DebugWebSocket)
        return;

    char buffer[1024];
    char submessage[128];
    uint32_t sublength = 0;

    uint32_t len = dmSnPrintf(buffer, sizeof(buffer), "%s '", msg);

    const uint8_t* bytes = (const uint8_t*)_bytes;
    for (uint32_t i = 0; i < num_bytes; ++i)
    {
        if (len + 2 >= sizeof(buffer))
        {
            dmLogWarning("%s", buffer);
            buffer[0] = 0;
            len = 0;
        }

        sublength = 0;

        int c = bytes[i];
        if (isprint(c))
            sublength = dmSnPrintf(submessage, sizeof(submessage), "%c", c);
        else if (c == '\r')
            sublength = dmSnPrintf(submessage, sizeof(submessage), "\\r");
        else if (c == '\n')
            sublength = dmSnPrintf(submessage, sizeof(submessage), "\\n");
        else if (c == '\t')
            sublength = dmSnPrintf(submessage, sizeof(submessage), "\\t");
        else
            sublength = dmSnPrintf(submessage, sizeof(submessage), "\\%02x", c);
        dmStrlCat(buffer, submessage, sizeof(buffer));
        len += sublength;
    }

    if (len + 2 >= sizeof(buffer))
    {
        dmLogWarning("%s", buffer);
        buffer[0] = 0;
        len = 0;
    }

    sublength = dmSnPrintf(submessage, sizeof(submessage), "' %u bytes", num_bytes);
    dmStrlCat(buffer, submessage, sizeof(buffer));
    len += sublength;
    dmLogWarning("%s", buffer);
}


#define CLOSE_CONN(...) \
    SetStatus(conn, RESULT_ERROR, __VA_ARGS__); \
    CloseConnection(conn);


static void SetState(WebsocketConnection* conn, State state)
{
    State prev_state = conn->m_State;
    if (prev_state != state)
    {
        conn->m_State = state;
        DebugLog(1, "%s -> %s", StateToString(prev_state), StateToString(conn->m_State));
    }
}


Result SetStatus(WebsocketConnection* conn, Result status, const char* format, ...)
{
    if (conn->m_Status == RESULT_OK)
    {
        va_list lst;
        va_start(lst, format);

        conn->m_BufferSize = vsnprintf(conn->m_Buffer, conn->m_BufferCapacity, format, lst);
        va_end(lst);
        conn->m_Status = status;

        DebugLog(1, "STATUS: '%s'  len: %u", conn->m_Buffer, conn->m_BufferSize);
    }
    return status;
}

// ***************************************************************************************************
// LUA functions



static WebsocketConnection* CreateConnection(const char* url)
{
    WebsocketConnection* conn = new WebsocketConnection;
    conn->m_BufferCapacity = g_Websocket.m_BufferSize;
    conn->m_Buffer = (char*)malloc(conn->m_BufferCapacity);
    conn->m_Buffer[0] = 0;
    conn->m_BufferSize = 0;
    conn->m_ConnectTimeout = 0;

    dmURI::Parse(url, &conn->m_Url);

    if (strcmp(conn->m_Url.m_Scheme, "https") == 0)
        strcpy(conn->m_Url.m_Scheme, "wss");

    conn->m_SSL = strcmp(conn->m_Url.m_Scheme, "wss") == 0 ? 1 : 0;
    conn->m_State = STATE_CONNECTING;

    conn->m_Callback = 0;
    conn->m_Connection = 0;
    conn->m_Socket = 0;
    conn->m_SSLSocket = 0;
    conn->m_Status = RESULT_OK;
    conn->m_HasHandshakeData = 0;
    conn->m_HandshakeResponse = 0;

#if defined(HAVE_WSLAY)
    conn->m_Ctx = 0;
#endif

    return conn;
}

static void DestroyConnection(WebsocketConnection* conn)
{
#if defined(HAVE_WSLAY)
    if (conn->m_Ctx)
        WSL_Exit(conn->m_Ctx);
#endif

    free((void*)conn->m_CustomHeaders);
    free((void*)conn->m_Protocol);

    if (conn->m_Callback)
        dmScript::DestroyCallback(conn->m_Callback);

#if defined(__EMSCRIPTEN__)
    if (conn->m_Socket != dmSocket::INVALID_SOCKET_HANDLE) {
        // We would normally do a shutdown() first, but Emscripten returns ENOSYS
        //dmSocket::Shutdown(conn->m_Socket, dmSocket::SHUTDOWNTYPE_READWRITE);
        dmSocket::Delete(conn->m_Socket);
    }
#else
    if (conn->m_Connection)
        dmConnectionPool::Close(g_Websocket.m_Pool, conn->m_Connection);
#endif

    if (conn->m_HandshakeResponse)
        delete conn->m_HandshakeResponse;


    free((void*)conn->m_Buffer);
    delete conn;
    DebugLog(2, "DestroyConnection: %p", conn);
}


static void CloseConnection(WebsocketConnection* conn)
{
    // we want it to send this message in the polling
    if (conn->m_State == STATE_CONNECTED) {
#if defined(HAVE_WSLAY)
        WSL_Close(conn->m_Ctx);
#endif
    }

    SetState(conn, STATE_DISCONNECTED);
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
    lua_Number timeout = dmScript::CheckTableNumber(L, 2, "timeout", 3000);
    const char* custom_headers = dmScript::CheckTableString(L, 2, "headers", 0);
    const char* protocol = dmScript::CheckTableString(L, 2, "protocol", 0);

    if (custom_headers != 0)
    {
        if (strstr(custom_headers, "\r\n\r\n") != 0)
        {
            return DM_LUA_ERROR("The header field must not contain double '\\r\\n\\r\\n': '%s'", custom_headers);
        }
    }

    WebsocketConnection* conn = CreateConnection(url);
    conn->m_ConnectTimeout = dmTime::GetTime() + timeout * 1000;
    conn->m_CustomHeaders = custom_headers ? strdup(custom_headers) : 0;
    conn->m_Protocol = protocol ? strdup(protocol) : 0;

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

#if defined(HAVE_WSLAY)
    int write_mode = dmScript::CheckTableNumber(L, 3, "type", WSLAY_BINARY_FRAME);

    struct wslay_event_msg msg;
    msg.opcode = write_mode;
    msg.msg = (const uint8_t*)string;
    msg.msg_length = string_length;

    wslay_event_queue_msg(conn->m_Ctx, &msg); // it makes a copy of the data
#else

    dmSocket::Result sr = Send(conn, string, string_length, 0);
    if (dmSocket::RESULT_OK != sr)
    {
        CLOSE_CONN("Failed to send on websocket");
    }
#endif

    return 0;
}

static void HandleCallback(WebsocketConnection* conn, int event, int msg_offset, int msg_length)
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

    lua_pushlstring(L, conn->m_Buffer + msg_offset, msg_length);
    lua_setfield(L, -2, "message");

    if(conn->m_HandshakeResponse)
    {
        HandshakeResponse* response = conn->m_HandshakeResponse;

        lua_newtable(L);

        lua_pushnumber(L, response->m_ResponseStatusCode);
        lua_setfield(L, -2, "status");

        lua_pushstring(L, &conn->m_Buffer[response->m_BodyOffset]);
        lua_setfield(L, -2, "response");

        lua_newtable(L);
        for (uint32_t i = 0; i < response->m_Headers.Size(); ++i)
        {
            lua_pushstring(L, response->m_Headers[i]->m_Value);
            lua_setfield(L, -2, response->m_Headers[i]->m_Key);
        }
        lua_setfield(L, -2, "headers");

        lua_setfield(L, -2, "handshake_response");

        delete conn->m_HandshakeResponse;
        conn->m_HandshakeResponse = 0;
    }

    dmScript::PCall(L, 3, 0);

    dmScript::TeardownCallback(conn->m_Callback);
}


HttpHeader::HttpHeader(const char* key, const char* value)
{
    m_Key = strdup(key);
    m_Value = strdup(value);
}

HttpHeader::~HttpHeader()
{
    free((void*)m_Key);
    free((void*)m_Value);
    m_Key = 0;
    m_Value = 0;
}

HttpHeader* HandshakeResponse::GetHeader(const char* header_key)
{
    for(uint32_t i = 0; i < m_Headers.Size(); ++i)
    {
        if (dmStrCaseCmp(m_Headers[i]->m_Key, header_key) == 0)
        {
            return m_Headers[i];
        }
    }

    return 0;
}

HandshakeResponse::~HandshakeResponse()
{
    for(uint32_t i = 0; i < m_Headers.Size(); ++i)
    {
        delete m_Headers[i];
    }
}


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

#define SETCONSTANT(_X) \
        lua_pushnumber(L, (lua_Number) _X); \
        lua_setfield(L, -2, #_X);

    SETCONSTANT(EVENT_CONNECTED);
    SETCONSTANT(EVENT_DISCONNECTED);
    SETCONSTANT(EVENT_MESSAGE);
    SETCONSTANT(EVENT_ERROR);

#if defined(HAVE_WSLAY)
    lua_pushnumber(L, (lua_Number) WSLAY_BINARY_FRAME);
    lua_setfield(L, -2, "DATA_TYPE_BINARY");
    lua_pushnumber(L, (lua_Number) WSLAY_TEXT_FRAME);
    lua_setfield(L, -2, "DATA_TYPE_TEXT");
#else
    SETCONSTANT(DATA_TYPE_BINARY);
    SETCONSTANT(DATA_TYPE_TEXT);
#endif

#undef SETCONSTANT

    lua_pop(L, 1);
    assert(top == lua_gettop(L));
}

static dmExtension::Result AppInitialize(dmExtension::AppParams* params)
{
    g_Websocket.m_BufferSize = dmConfigFile::GetInt(params->m_ConfigFile, "websocket.buffer_size", 64 * 1024);
    g_Websocket.m_Timeout = dmConfigFile::GetInt(params->m_ConfigFile, "websocket.socket_timeout", 500 * 1000);
    g_Websocket.m_Connections.SetCapacity(4);
    g_Websocket.m_Channel = 0;
    g_Websocket.m_Pool = 0;

    dmConnectionPool::Params pool_params;
    pool_params.m_MaxConnections = dmConfigFile::GetInt(params->m_ConfigFile, "websocket.max_connections", 2);
    dmConnectionPool::Result result = dmConnectionPool::New(&pool_params, &g_Websocket.m_Pool);

    g_DebugWebSocket = dmConfigFile::GetInt(params->m_ConfigFile, "websocket.debug", 0);
    if (g_DebugWebSocket)
        dmLogInfo("dmWebSocket::g_DebugWebSocket == %d", g_DebugWebSocket);

    if (dmConnectionPool::RESULT_OK != result)
    {
        dmLogError("Failed to create connection pool: %d", result);
    }

// We can do without the channel, it will then fallback to the dmSocket::GetHostname (as opposed to dmDNS::GetHostname)
#if defined(HAVE_WSLAY)
    dmDNS::Result dns_result = dmDNS::NewChannel(&g_Websocket.m_Channel);

    if (dmDNS::RESULT_OK != dns_result)
    {
        dmLogError("Failed to create connection pool: %d", dns_result);
    }
#endif

#if defined(__EMSCRIPTEN__)
    // avoid mixed content warning if trying to access wss resource from http page
    // If not using this, we get EHOSTUNREACH
    EM_ASM({
        Module["websocket"].url = window["location"]["protocol"].replace("http", "ws") + "//";
    });
#endif

    g_Websocket.m_Initialized = 1;
    if (!g_Websocket.m_Pool)
    {
        if (!g_Websocket.m_Pool)
        {
            dmLogInfo("pool is null!");
            dmConnectionPool::Delete(g_Websocket.m_Pool);
        }

        dmLogInfo("%s extension not initialized", MODULE_NAME);
        g_Websocket.m_Initialized = 0;
    }

    return dmExtension::RESULT_OK;
}

static dmExtension::Result Initialize(dmExtension::Params* params)
{
    if (!g_Websocket.m_Initialized)
        return dmExtension::RESULT_OK;

    LuaInit(params->m_L);
    dmLogInfo("Registered %s extension", MODULE_NAME);

    return dmExtension::RESULT_OK;
}

static dmExtension::Result AppFinalize(dmExtension::AppParams* params)
{

    dmConnectionPool::Shutdown(g_Websocket.m_Pool, dmSocket::SHUTDOWNTYPE_READWRITE);
    return dmExtension::RESULT_OK;
}

static dmExtension::Result Finalize(dmExtension::Params* params)
{
    while (!g_Websocket.m_Connections.Empty())
    {
        WebsocketConnection* conn = g_Websocket.m_Connections.Back();
        g_Websocket.m_Connections.Pop();
        DestroyConnection(conn);
    }
    return dmExtension::RESULT_OK;
}

Result PushMessage(WebsocketConnection* conn, MessageType type, int length, const uint8_t* buffer)
{
    if (conn->m_Messages.Full())
        conn->m_Messages.OffsetCapacity(4);

    Message msg;
    msg.m_Type = (uint32_t)type;
    msg.m_Length = length;
    conn->m_Messages.Push(msg);

    // No need to copy itself (html5)
    if (buffer != (const uint8_t*)conn->m_Buffer)
    {
        if ((conn->m_BufferSize + length) >= conn->m_BufferCapacity)
        {
            conn->m_BufferCapacity = conn->m_BufferSize + length + 1;
            conn->m_Buffer = (char*)realloc(conn->m_Buffer, conn->m_BufferCapacity);
        }
        // append to the end of the buffer
        memcpy(conn->m_Buffer + conn->m_BufferSize, buffer, length);
    }

    conn->m_BufferSize += length;
    conn->m_Buffer[conn->m_BufferCapacity-1] = 0;

    // Instead of printing from the incoming buffer, we print from our own, to make sure it looks ok
    DebugPrint(2, __FUNCTION__, conn->m_Buffer+conn->m_BufferSize-length, length);

    return dmWebsocket::RESULT_OK;
}

// has the connect procedure taken too long?
static bool CheckConnectTimeout(WebsocketConnection* conn)
{
    uint64_t t = dmTime::GetTime();
    return t >= conn->m_ConnectTimeout;
}

static dmExtension::Result OnUpdate(dmExtension::Params* params)
{
    uint32_t size = g_Websocket.m_Connections.Size();

    for (uint32_t i = 0; i < size; ++i)
    {
        WebsocketConnection* conn = g_Websocket.m_Connections[i];

        if (STATE_DISCONNECTED == conn->m_State)
        {
            if (RESULT_OK != conn->m_Status)
            {
                HandleCallback(conn, EVENT_ERROR, 0, conn->m_BufferSize);
                conn->m_BufferSize = 0;
            }

            HandleCallback(conn, EVENT_DISCONNECTED, 0, conn->m_BufferSize);

            g_Websocket.m_Connections.EraseSwap(i);
            --i;
            --size;
            DestroyConnection(conn);
        }
        else if (STATE_CONNECTED == conn->m_State)
        {
#if defined(HAVE_WSLAY)
            int r = WSL_Poll(conn->m_Ctx);
            if (0 != r)
            {
                CLOSE_CONN("Websocket closing for %s (%s)", conn->m_Url.m_Hostname, WSL_ResultToString(r));
                continue;
            }
#else
            int recv_bytes = 0;
            dmSocket::Result sr = Receive(conn, conn->m_Buffer, conn->m_BufferCapacity-1, &recv_bytes);
            if( sr == dmSocket::RESULT_WOULDBLOCK )
            {
                continue;
            }

            if (dmSocket::RESULT_OK == sr)
            {
                PushMessage(conn, MESSAGE_TYPE_NORMAL, recv_bytes, (const uint8_t*)conn->m_Buffer);
            }
            else
            {
                CLOSE_CONN("Websocket failed to receive data %s", dmSocket::ResultToString(sr));
                continue;
            }
#endif

            uint32_t offset = 0;
            bool close_received = false;
            for (uint32_t i = 0; i < conn->m_Messages.Size(); ++i)
            {
                const Message& msg = conn->m_Messages[i];

                if (EVENT_DISCONNECTED == msg.m_Type)
                {
                    conn->m_Status = RESULT_OK;
                    CloseConnection(conn);

                    // Put the message at the front of the buffer
                    conn->m_Messages.SetSize(0);
                    conn->m_BufferSize = 0;
                    PushMessage(conn, MESSAGE_TYPE_CLOSE, msg.m_Length, (const uint8_t*)conn->m_Buffer+offset);
                    close_received = true;
                    break;
                }

                HandleCallback(conn, EVENT_MESSAGE, offset, msg.m_Length);
                offset += msg.m_Length;
            }
            if (!close_received) // saving the close message for next step
            {
                conn->m_Messages.SetSize(0);
                conn->m_BufferSize = 0;
            }
        }
        else if (STATE_HANDSHAKE_READ == conn->m_State)
        {
            if (CheckConnectTimeout(conn))
            {
                CLOSE_CONN("Connect sequence timed out");
                continue;
            }

            Result result = ReceiveHeaders(conn);
            if (RESULT_WOULDBLOCK == result)
            {
                continue;
            }

            if (RESULT_OK != result)
            {
                CLOSE_CONN("Failed receiving handshake headers. %d", result);
                continue;
            }

            // Verifies headers, and also stages any initial sent data
            result = VerifyHeaders(conn);
            if (RESULT_OK != result)
            {
                CLOSE_CONN("Failed verifying handshake headers:\n%s\n\n", conn->m_Buffer);
                continue;
            }

#if defined(HAVE_WSLAY)
            int r = WSL_Init(&conn->m_Ctx, g_Websocket.m_BufferSize, (void*)conn);
            if (0 != r)
            {
                CLOSE_CONN("Failed initializing wslay: %s", WSL_ResultToString(r));
                continue;
            }

            dmSocket::SetNoDelay(conn->m_Socket, true);
            // Don't go lower than 1000 since some platforms might not have that good precision
            dmSocket::SetReceiveTimeout(conn->m_Socket, 1000);
            if (conn->m_SSLSocket)
                dmSSLSocket::SetReceiveTimeout(conn->m_SSLSocket, 1000);
#endif
            dmSocket::SetBlocking(conn->m_Socket, false);

            SetState(conn, STATE_CONNECTED);
            HandleCallback(conn, EVENT_CONNECTED, 0, 0);
        }
        else if (STATE_HANDSHAKE_WRITE == conn->m_State)
        {
            if (CheckConnectTimeout(conn))
            {
                CLOSE_CONN("Connect sequence timed out");
                continue;
            }

            Result result = SendClientHandshake(conn);
            if (RESULT_WOULDBLOCK == result)
            {
                continue;
            }
            if (RESULT_OK != result)
            {
                CLOSE_CONN("Failed sending handshake: %d", result);
                continue;
            }

            SetState(conn, STATE_HANDSHAKE_READ);
        }
        else if (STATE_CONNECTING == conn->m_State)
        {
            if (CheckConnectTimeout(conn))
            {
                CLOSE_CONN("Connect sequence timed out");
                continue;
            }

#if defined(__EMSCRIPTEN__)
            conn->m_SSLSocket = dmSSLSocket::INVALID_SOCKET_HANDLE;

            EM_ASM({
                // https://emscripten.org/docs/porting/networking.html#emulated-posix-tcp-sockets-over-websockets
                Module["websocket"]["subprotocol"] = $0 ? UTF8ToString($0) : null;
            }, conn->m_Protocol);

            char uri_buffer[dmURI::MAX_URI_LEN];
            const char* uri;
            if (conn->m_Url.m_Path[0] != '\0') {
                dmSnPrintf(uri_buffer, sizeof(uri_buffer), "%s%s", conn->m_Url.m_Hostname, conn->m_Url.m_Path);
                uri = uri_buffer;
            } else {
                uri = conn->m_Url.m_Hostname;
            }

            dmSocket::Address address;
            dmSocket::Result sr = dmSocket::GetHostByName(uri, &address, true, false);
            if (dmSocket::RESULT_OK != sr) {
                CLOSE_CONN("Failed to get address from host name '%s': %s", uri, dmSocket::ResultToString(sr));
                continue;
            }

            sr = dmSocket::New(address.m_family, dmSocket::TYPE_STREAM, dmSocket::PROTOCOL_TCP, &conn->m_Socket);
            if (dmSocket::RESULT_OK != sr) {
                CLOSE_CONN("Failed to create socket for '%s': %s", conn->m_Url.m_Hostname, dmSocket::ResultToString(sr));
                continue;
            }

            sr = dmSocket::Connect(conn->m_Socket, address, conn->m_Url.m_Port);
            if (dmSocket::RESULT_OK != sr) {
                CLOSE_CONN("Failed to connect to '%s:%d': %s", conn->m_Url.m_Hostname, (int)conn->m_Url.m_Port, dmSocket::ResultToString(sr));
                continue;
            }
#else
            dmSocket::Result sr;
            int timeout = g_Websocket.m_Timeout;
            dmConnectionPool::Result pool_result = dmConnectionPool::Dial(g_Websocket.m_Pool, conn->m_Url.m_Hostname, conn->m_Url.m_Port, g_Websocket.m_Channel, conn->m_SSL, timeout, &conn->m_Connection, &sr);
            if (dmConnectionPool::RESULT_OK != pool_result)
            {
                CLOSE_CONN("Failed to open connection: %s", dmSocket::ResultToString(sr));
                continue;
            }
            conn->m_Socket = dmConnectionPool::GetSocket(g_Websocket.m_Pool, conn->m_Connection);
            conn->m_SSLSocket = dmConnectionPool::GetSSLSocket(g_Websocket.m_Pool, conn->m_Connection);
#endif

            SetState(conn, STATE_HANDSHAKE_WRITE);
        }
    }

    return dmExtension::RESULT_OK;
}

} // dmWebsocket

DM_DECLARE_EXTENSION(Websocket, LIB_NAME, dmWebsocket::AppInitialize, dmWebsocket::AppFinalize, dmWebsocket::Initialize, dmWebsocket::OnUpdate, 0, dmWebsocket::Finalize)

#undef CLOSE_CONN
