#include "websocket.h"
#include <dmsdk/dlib/socket.h>
#include <dmsdk/dlib/http_client.h>
#include <ctype.h> // tolower

namespace dmWebsocket
{

const char* RFC_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // as per the rfc document on page 7 (https://tools.ietf.org/html/rfc6455)

static void CreateKey(uint8_t* key, size_t len)
{
    pcg32_random_t rnd;
    pcg32_srandom_r(&rnd, dmTime::GetTime(), 31452);
    for (unsigned int i = 0; i < len; i++) {
        key[i] = (char)(uint8_t)(pcg32_random_r(&rnd) & 0xFF);
    }
}

#define WS_SENDALL(s) \
    sr = Send(conn, s, strlen(s), 0);\
    if (sr != dmSocket::RESULT_OK)\
    {\
        goto bail;\
    }\

static Result SendClientHandshakeHeaders(WebsocketConnection* conn)
{
    CreateKey(conn->m_Key, sizeof(conn->m_Key));

    char encoded_key[64] = {0};
    uint32_t encoded_key_len = sizeof(encoded_key);

    if (!dmCrypt::Base64Encode((const unsigned char*)conn->m_Key, sizeof(conn->m_Key), (unsigned char*)encoded_key, &encoded_key_len))
    {
        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Failed to base64 encode key");
    }

    char port[8] = "";
    if (!(conn->m_Url.m_Port == 80 || conn->m_Url.m_Port == 443))
        dmSnPrintf(port, sizeof(port), ":%d", conn->m_Url.m_Port);

    dmSocket::Result sr;
    WS_SENDALL("GET ");
    if (conn->m_Url.m_Path[0] == '\0') {
        WS_SENDALL("/"); // Default to / for empty path
    } else {
        WS_SENDALL(conn->m_Url.m_Path);
    }
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

    if (conn->m_CustomHeaders)
    {
        WS_SENDALL(conn->m_CustomHeaders);
        // make sure we ended with '\r\n'
        int len = strlen(conn->m_CustomHeaders);
        bool ended_with_sentinel = len >= 2 && conn->m_CustomHeaders[len - 2] == '\r' && conn->m_CustomHeaders[len - 1] == '\n';
        if (!ended_with_sentinel)
        {
            WS_SENDALL("\r\n");
        }
    }

    if (conn->m_Protocol) {
        WS_SENDALL("Sec-WebSocket-Protocol: ");
        WS_SENDALL(conn->m_Protocol);
        WS_SENDALL("\r\n");
    }

    WS_SENDALL("\r\n");

bail:
    if (sr != dmSocket::RESULT_OK)
    {
        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "SendClientHandshake failed: %s", dmSocket::ResultToString(sr));
    }

    return RESULT_OK;
}

#undef WS_SENDALL

Result SendClientHandshake(WebsocketConnection* conn)
{
    dmSocket::Result sr = WaitForSocket(conn, dmSocket::SELECTOR_KIND_WRITE, SOCKET_WAIT_TIMEOUT);
    if (dmSocket::RESULT_WOULDBLOCK == sr)
    {
        return RESULT_WOULDBLOCK;
    }
    if (dmSocket::RESULT_OK != sr)
    {
        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Connection not ready for sending data: %s", dmSocket::ResultToString(sr));
    }

// In emscripten, the sockets are actually already websockets, so no handshake necessary
#if defined(__EMSCRIPTEN__)
    return RESULT_OK;
#else
    return SendClientHandshakeHeaders(conn);
#endif
}


#if defined(__EMSCRIPTEN__)
Result ReceiveHeaders(WebsocketConnection* conn)
{
    return RESULT_OK;
}

#else
Result ReceiveHeaders(WebsocketConnection* conn)
{
    dmSocket::Result sr = WaitForSocket(conn, dmSocket::SELECTOR_KIND_READ, SOCKET_WAIT_TIMEOUT);
    if (dmSocket::RESULT_OK != sr)
    {
        if (dmSocket::RESULT_WOULDBLOCK)
        {
            DebugLog(2, "Waiting for socket to be available for reading");
            return RESULT_WOULDBLOCK;
        }

        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Failed waiting for more handshake headers: %s", dmSocket::ResultToString(sr));
    }

    int max_to_recv = (int)(conn->m_BufferCapacity - 1) - conn->m_BufferSize; // allow for a terminating null character

    if (max_to_recv <= 0)
    {
        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Receive buffer full: %u bytes", conn->m_BufferCapacity);
    }

    int recv_bytes = 0;
    sr = Receive(conn, conn->m_Buffer + conn->m_BufferSize, max_to_recv, &recv_bytes);

    if( sr == dmSocket::RESULT_WOULDBLOCK )
    {
        sr = dmSocket::RESULT_TRY_AGAIN;
    }

    if (sr == dmSocket::RESULT_TRY_AGAIN)
        return RESULT_WOULDBLOCK;

    if (sr != dmSocket::RESULT_OK)
    {
        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Receive error: %s", dmSocket::ResultToString(sr));
    }

    conn->m_BufferSize += recv_bytes;

    // NOTE: We have an extra byte for null-termination so no buffer overrun here.
    conn->m_Buffer[conn->m_BufferSize] = '\0';

    // Check if the end of the response has arrived
    const char* endtag = strstr(conn->m_Buffer, "\r\n\r\n");
    if (endtag != 0)
    {
        return RESULT_OK;
    }

    return RESULT_WOULDBLOCK;
}
#endif

static void HandleVersion(void* user_data, int major, int minor, int status, const char* status_str)
{
    HandshakeResponse* response = (HandshakeResponse*)user_data;
    response->m_HttpMajor = major;
    response->m_HttpMinor = minor;
    response->m_ResponseStatusCode = status;
}


static void HandleHeader(void* user_data, const char* key, const char* value)
{
    HandshakeResponse* response = (HandshakeResponse*)user_data;
    if (response->m_Headers.Remaining() == 0)
    {
        response->m_Headers.OffsetCapacity(4);
    }
    HttpHeader* new_header = new HttpHeader(key, value);

    response->m_Headers.Push(new_header);
}


static void HandleContent(void* user_data, int offset)
{
    HandshakeResponse* response = (HandshakeResponse*)user_data;
    response->m_BodyOffset = offset;
}


bool ValidateSecretKey(WebsocketConnection* conn, const char* server_key)
{
    uint8_t client_key[32 + 40];
    uint32_t client_key_len = sizeof(client_key);
    dmCrypt::Base64Encode(conn->m_Key, sizeof(conn->m_Key), client_key, &client_key_len);
    client_key[client_key_len] = 0;

    DebugLog(2, "Secret key (base64): %s", client_key);

    memcpy(client_key + client_key_len, RFC_MAGIC, strlen(RFC_MAGIC));
    client_key_len += strlen(RFC_MAGIC);
    client_key[client_key_len] = 0;

    DebugLog(2, "Secret key + RFC_MAGIC: %s", client_key);

    uint8_t client_key_sha1[20];
    dmCrypt::HashSha1(client_key, client_key_len, client_key_sha1);

    DebugPrint(2, "Hashed key (sha1):", client_key_sha1, sizeof(client_key_sha1));

    client_key_len = sizeof(client_key);
    dmCrypt::Base64Encode(client_key_sha1, sizeof(client_key_sha1), client_key, &client_key_len);
    client_key[client_key_len] = 0;
    DebugLog(2, "Client key (base64): %s", client_key);
    DebugLog(2, "Server key (base64): %s", server_key);

    return strcmp(server_key, (const char*)client_key) == 0;
}


#if defined(__EMSCRIPTEN__)
Result VerifyHeaders(WebsocketConnection* conn)
{
    return RESULT_OK;
}
#else
Result VerifyHeaders(WebsocketConnection* conn)
{
    char* r = conn->m_Buffer;

    // Find start of payload now because dmHttpClient::ParseHeader is destructive
    const char* start_of_payload = strstr(conn->m_Buffer, "\r\n\r\n");
    start_of_payload += 4;

    HandshakeResponse* response = new HandshakeResponse();
    conn->m_HandshakeResponse = response;
    dmHttpClient::ParseResult parse_result = dmHttpClient::ParseHeader(r, response, true, &HandleVersion, &HandleHeader, &HandleContent);
    if (parse_result != dmHttpClient::ParseResult::PARSE_RESULT_OK)
    {
        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Failed to parse handshake response. 'dmHttpClient::ParseResult=%i'", parse_result);
    }

    if (response->m_ResponseStatusCode != 101) {
        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Wrong response status: %i", response->m_ResponseStatusCode);
    }

    HttpHeader *connection_header, *upgrade_header, *websocket_secret_header;
    connection_header = response->GetHeader("Connection");
    upgrade_header = response->GetHeader("Upgrade");
    websocket_secret_header = response->GetHeader("Sec-WebSocket-Accept");
    bool connection = connection_header && dmStrCaseCmp(connection_header->m_Value, "Upgrade") == 0;
    bool upgrade  = upgrade_header && dmStrCaseCmp(upgrade_header->m_Value, "websocket") == 0;
    bool valid_key = websocket_secret_header && ValidateSecretKey(conn, websocket_secret_header->m_Value);

    // Send error to lua?
    if (!connection)
        dmLogError("Failed to find the Connection keyword in the response headers");
    if (!upgrade)
        dmLogError("Failed to find the Upgrade keyword in the response headers");
    if (!valid_key)
        dmLogError("Failed to find valid key in the response headers");

    bool ok = connection && upgrade && valid_key;
    if(!ok)
    {
        return RESULT_HANDSHAKE_FAILED;
    }

    delete conn->m_HandshakeResponse;
    conn->m_HandshakeResponse = 0;

    // The response might contain both the headers, but also (if successful) the first batch of data
    uint32_t size = conn->m_BufferSize - (start_of_payload - conn->m_Buffer);
    conn->m_BufferSize = size;
    memmove(conn->m_Buffer, start_of_payload, size);
    conn->m_Buffer[size] = 0;
    conn->m_HasHandshakeData = conn->m_BufferSize != 0 ? 1 : 0;
    return RESULT_OK;
}
#endif

} // namespace