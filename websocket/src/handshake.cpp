#include "websocket.h"
#include <dmsdk/dlib/socket.h>

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
    dmSocket::Selector selector;
    dmSocket::SelectorZero(&selector);
    dmSocket::SelectorSet(&selector, dmSocket::SELECTOR_KIND_READ, conn->m_Socket);

    dmSocket::Result sr = dmSocket::Select(&selector, 200*1000);

    if (dmSocket::RESULT_OK != sr)
    {
        if (dmSocket::RESULT_WOULDBLOCK)
        {
            dmLogWarning("Waiting for socket to be available for reading");
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
    if (conn->m_BufferSize >= 4 && strcmp(conn->m_Buffer + conn->m_BufferSize - 4, "\r\n\r\n") == 0)
    {
        return RESULT_OK;
    }

    return RESULT_WOULDBLOCK;
}
#endif

#if defined(__EMSCRIPTEN__)
Result VerifyHeaders(WebsocketConnection* conn)
{
    return RESULT_OK;
}
#else
Result VerifyHeaders(WebsocketConnection* conn)
{
    char* r = conn->m_Buffer;

    // According to protocol, the response should start with "HTTP/1.1 <statuscode> <message>"
    const char* http_version_and_status_protocol = "HTTP/1.1 101";
    if (strstr(r, http_version_and_status_protocol) != r) {
        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Missing: '%s' in header", http_version_and_status_protocol);
    }

    r = strstr(r, "\r\n") + 2;

    bool upgraded = false;
    bool valid_key = false;
    const char* protocol = "";

    // TODO: Perhaps also support the Sec-WebSocket-Protocol

    // parse the headers in place
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

        if (strcmp(key, "Connection") == 0 && strcmp(value, "Upgrade") == 0)
            upgraded = true;
        else if (strcmp(key, "Sec-WebSocket-Accept") == 0)
        {

            uint8_t client_key[32 + 40];
            uint32_t client_key_len = sizeof(client_key);
            dmCrypt::Base64Encode(conn->m_Key, sizeof(conn->m_Key), client_key, &client_key_len);
            client_key[client_key_len] = 0;

            memcpy(client_key + client_key_len, RFC_MAGIC, strlen(RFC_MAGIC));
            client_key_len += strlen(RFC_MAGIC);
            client_key[client_key_len] = 0;

            uint8_t client_key_sha1[20];
            dmCrypt::HashSha1(client_key, client_key_len, client_key_sha1);

            client_key_len = sizeof(client_key);
            dmCrypt::Base64Encode(client_key_sha1, sizeof(client_key_sha1), client_key, &client_key_len);
            client_key[client_key_len] = 0;

            if (strcmp(value, (const char*)client_key) == 0)
                valid_key = true;
        }

        if (strcmp(r, "\r\n") == 0)
            break;
    }

    if (!upgraded)
        dmLogError("Failed to find the Upgrade keyword in the response headers");
    if (!valid_key)
        dmLogError("Failed to find valid key in the response headers");

    if (!(upgraded && valid_key)) {
        dmLogError("Response:\n\"%s\"\n", conn->m_Buffer);
    }

    return (upgraded && valid_key) ? RESULT_OK : RESULT_HANDSHAKE_FAILED;
}
#endif

} // namespace