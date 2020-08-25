#include "dmsdk/socket.h"
#include "websocket.h"

namespace dmWebsocket
{

extern void debugPrintBuffer(const char* s, size_t len);

dmSocket::Result Send(WebsocketConnection* conn, const char* buffer, int length, int* out_sent_bytes)
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

dmSocket::Result Receive(WebsocketConnection* conn, void* buffer, int length, int* received_bytes)
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

} // namespace