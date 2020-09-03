#include "websocket.h"

#if defined(HAVE_WSLAY)

namespace dmWebsocket
{

const struct wslay_event_callbacks g_WslCallbacks = {
    WSL_RecvCallback,
    WSL_SendCallback,
    WSL_GenmaskCallback,
    NULL,
    NULL,
    NULL,
    WSL_OnMsgRecvCallback
};

#define WSLAY_CASE(_X) case _X: return #_X;

const char* WSL_ResultToString(int err)
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


int WSL_Init(wslay_event_context_ptr* ctx, ssize_t buffer_size, void* userctx)
{
    // Currently only supports client implementation
    int ret = -1;
    ret = wslay_event_context_client_init(ctx, &g_WslCallbacks, userctx);
    if (ret == 0)
        wslay_event_config_set_max_recv_msg_length(*ctx, buffer_size);
    return ret;
}


void WSL_Exit(wslay_event_context_ptr ctx)
{
    wslay_event_context_free(ctx);
}

int WSL_Close(wslay_event_context_ptr ctx)
{
    const char* reason = "Client wants to close";
    wslay_event_queue_close(ctx, 0, (const uint8_t*)reason, strlen(reason));
    return 0;
}

int WSL_Poll(wslay_event_context_ptr ctx)
{
    int r = 0;
    if ((r = wslay_event_recv(ctx)) != 0 || (r = wslay_event_send(ctx)) != 0) {
        dmLogError("Websocket poll error: %s", WSL_ResultToString(r));
    }
    return r;
}

int WSL_WantsExit(wslay_event_context_ptr ctx)
{
    if ((wslay_event_get_close_sent(ctx) && wslay_event_get_close_received(ctx))) {
        return 1;
    }
    return 0;
}

ssize_t WSL_RecvCallback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *user_data)
{
    WebsocketConnection* conn = (WebsocketConnection*)user_data;

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

ssize_t WSL_SendCallback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data)
{
    WebsocketConnection* conn = (WebsocketConnection*)user_data;

    int sent_bytes = 0;
    dmSocket::Result socket_result = Send(conn, (const char*)data, len, &sent_bytes);

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

void WSL_OnMsgRecvCallback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg, void *user_data)
{
    WebsocketConnection* conn = (WebsocketConnection*)user_data;
    if (arg->opcode == WSLAY_TEXT_FRAME || arg->opcode == WSLAY_BINARY_FRAME)
    {
        if (arg->msg_length >= conn->m_BufferCapacity)
            conn->m_Buffer = (char*)realloc(conn->m_Buffer, arg->msg_length + 1);
        memcpy(conn->m_Buffer, arg->msg, arg->msg_length);
        conn->m_BufferSize = arg->msg_length;
        conn->m_HasMessage = 1;

    } else if (arg->opcode == WSLAY_CONNECTION_CLOSE)
    {
        // TODO: Store the reason
    }
}

// ************************************************************************************************


int WSL_GenmaskCallback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data) {
    pcg32_random_t rnd;
    pcg32_srandom_r(&rnd, dmTime::GetTime(), 31452);
    for (unsigned int i = 0; i < len; i++) {
        buf[i] = (uint8_t)(pcg32_random_r(&rnd) & 0xFF);
    }
    return 0;
}

} // namespace

#endif // HAVE_WSLAY