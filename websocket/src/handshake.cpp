#include "websocket.h"
#include "dmsdk/socket.h"

namespace dmWebsocket
{

const char* RFC_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // as per the rfc document on page 7 (https://tools.ietf.org/html/rfc6455)


static void printHex(const uint8_t* data, size_t len)
{
    for (int i = 0; i < 16; ++i)
    {
        printf("%x", data[i]);
    }
}

static void CreateKey(uint8_t* key, size_t len)
{
    pcg32_random_t rnd;
    pcg32_srandom_r(&rnd, dmTime::GetTime(), 31452);
    for (unsigned int i = 0; i < len; i++) {
        key[i] = (char)(uint8_t)(pcg32_random_r(&rnd) & 0xFF);
    }
}

#define WS_SENDALL(s) \
    sock_res = Send(conn, s, strlen(s), 0);\
    if (sock_res != dmSocket::RESULT_OK)\
    {\
        goto bail;\
    }\

Result SendClientHandshake(WebsocketConnection* conn)
{
    CreateKey(conn->m_Key, sizeof(conn->m_Key));

    char encoded_key[64] = {0};
    uint32_t encoded_key_len = sizeof(encoded_key);

    //mbedtls_base64_encode((unsigned char*)encoded_key, sizeof(encoded_key), &encoded_key_len, (const unsigned char*)conn->m_Key, sizeof(conn->m_Key));
    if (!dmCrypt::Base64Encode((const unsigned char*)conn->m_Key, sizeof(conn->m_Key), (unsigned char*)encoded_key, &encoded_key_len))
    {
        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Failed to base64 encode key");
    }


printf("DBG: CreateKey: '");
printHex((const uint8_t*)conn->m_Key, 16);
printf("'\n");

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

bail:
    if (sock_res != dmSocket::RESULT_OK)
    {
        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "SendClientHandshake failed: %s", dmSocket::ResultToString(sock_res));
    }

    return RESULT_OK;
}

#undef WS_SENDALL


void debugPrintBuffer(const char* s, size_t len)
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

// Currently blocking!
Result ReceiveHeaders(WebsocketConnection* conn)
{
    while (1)
    {
        int max_to_recv = (int)(conn->m_BufferCapacity - 1) - conn->m_BufferSize; // allow for a terminating null character

        if (max_to_recv <= 0)
        {
            return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Receive buffer full: %u bytes", conn->m_BufferCapacity);
        }

        int recv_bytes = 0;
        dmSocket::Result r = Receive(conn, conn->m_Buffer + conn->m_BufferSize, max_to_recv, &recv_bytes);

        if( r == dmSocket::RESULT_WOULDBLOCK )
        {
            r = dmSocket::RESULT_TRY_AGAIN;
        }

        if (r == dmSocket::RESULT_TRY_AGAIN)
            continue;

        if (r != dmSocket::RESULT_OK)
        {
            return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Receive error: %s", dmSocket::ResultToString(r));
        }

debugPrintBuffer(conn->m_Buffer + conn->m_BufferSize, recv_bytes);

        conn->m_BufferSize += recv_bytes;

        // NOTE: We have an extra byte for null-termination so no buffer overrun here.
        conn->m_Buffer[conn->m_BufferSize] = '\0';

        // Check if the end of the response has arrived
        if (conn->m_BufferSize >= 4 && strcmp(conn->m_Buffer + conn->m_BufferSize - 4, "\r\n\r\n") == 0)
        {
            return RESULT_OK;
        }

        if (r == 0)
        {
            return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Failed to parse headers:\n%s", conn->m_Buffer);
        }
    }
}

Result VerifyHeaders(WebsocketConnection* conn)
{
    char* r = conn->m_Buffer;

    printf("SERVER RESPONSE:\n%s\n", r);

    const char* http_version_and_status_protocol = "HTTP/1.1 101"; // optionally "Web Socket Protocol Handshake"
    if (strstr(r, http_version_and_status_protocol) != r) {
        return SetStatus(conn, RESULT_HANDSHAKE_FAILED, "Missing: '%s' in header", http_version_and_status_protocol);
    }
    r = strstr(r, "\r\n") + 2;

    bool upgraded = false;
    bool valid_key = false;
    const char* protocol = "";

    // Sec-WebSocket-Protocol

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

printf("KEY: '%s', VALUE: '%s'\n", key, value);

        if (strcmp(key, "Connection") == 0 && strcmp(value, "Upgrade") == 0)
            upgraded = true;
        else if (strcmp(key, "Sec-WebSocket-Accept") == 0)
        {

            uint8_t client_key[32 + 40];
            uint32_t client_key_len = sizeof(client_key);
            //mbedtls_base64_encode((unsigned char*)client_key, sizeof(client_key), &client_key_len, (const unsigned char*)conn->m_Key, sizeof(conn->m_Key));
            dmCrypt::Base64Encode(conn->m_Key, sizeof(conn->m_Key), client_key, &client_key_len);
            client_key[client_key_len] = 0;

            memcpy(client_key + client_key_len, RFC_MAGIC, strlen(RFC_MAGIC));
            client_key_len += strlen(RFC_MAGIC);
            client_key[client_key_len] = 0;

            uint8_t client_key_sha1[20];
            dmCrypt::HashSha1(client_key, client_key_len, client_key_sha1);

            //mbedtls_base64_encode((unsigned char*)client_key, sizeof(client_key), &client_key_len, client_key_sha1, sizeof(client_key_sha1));
            client_key_len = sizeof(client_key);
            dmCrypt::Base64Encode(client_key_sha1, sizeof(client_key_sha1), client_key, &client_key_len);
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

} // namespace