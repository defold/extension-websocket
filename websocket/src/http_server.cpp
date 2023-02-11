// Copyright 2020-2022 The Defold Foundation
// Copyright 2014-2020 King
// Copyright 2009-2014 Ragnar Svensson, Christian Murray
// Licensed under the Defold License version 1.0 (the "License"); you may not use
// this file except in compliance with the License.
//
// You may obtain a copy of the License, together with FAQs at
// https://www.defold.com/license
//
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dmsdk/dlib/array.h>
#include <dmsdk/dlib/log.h>
#include <dmsdk/dlib/dstrings.h>
#include <dmsdk/dlib/time.h>
#include <dmsdk/dlib/math.h>
#include "http_server.h"

namespace wsHttpServer
{
    void SetDefaultParams(struct NewParams* params)
    {
        memset(params, 0, sizeof(*params));
        params->m_MaxConnections = 16;
        params->m_ConnectionTimeout = 60;
    }

    static void Disconnect(Server* server)
    {
        if (server->m_ServerSocket != dmSocket::INVALID_SOCKET_HANDLE)
        {
            dmSocket::Delete(server->m_ServerSocket);
            server->m_ServerSocket = dmSocket::INVALID_SOCKET_HANDLE;
        }
    }

    static Result Connect(Server* server, uint16_t port)
    {
        dmSocket::Socket socket = dmSocket::INVALID_SOCKET_HANDLE;
        dmSocket::Address bind_address;
        dmSocket::Result r = dmSocket::RESULT_OK;

        Disconnect(server);

        r = dmSocket::GetHostByName("0.0.0.0", &bind_address);
        if (r != dmSocket::RESULT_OK)
        {
            return RESULT_SOCKET_ERROR;
        }

        r = dmSocket::New(bind_address.m_family, dmSocket::TYPE_STREAM, dmSocket::PROTOCOL_TCP, &socket);
        if (r != dmSocket::RESULT_OK)
        {
            return RESULT_UNKNOWN;
        }

        dmSocket::SetReuseAddress(socket, true);

        r = dmSocket::Bind(socket, bind_address, port);
        if (r != dmSocket::RESULT_OK)
        {
            dmSocket::Delete(socket);
            return RESULT_SOCKET_ERROR;
        }

        r = dmSocket::Listen(socket, 32);
        if (r != dmSocket::RESULT_OK)
        {
            dmSocket::Delete(socket);
            return RESULT_SOCKET_ERROR;
        }

        dmSocket::Address address;
        uint16_t actual_port;
        r = dmSocket::GetName(socket, &address, &actual_port);
        if (r != dmSocket::RESULT_OK)
        {
            dmSocket::Delete(socket);
            return RESULT_SOCKET_ERROR;
        }

        server->m_Address = address;
        server->m_Port = actual_port;
        server->m_ServerSocket = socket;

        return RESULT_OK;
    }

    Result New(const NewParams* params, uint16_t port, HServer* server)
    {
        *server = 0;

        if (!params->m_HttpRequest)
            return RESULT_ERROR_INVAL;

        Server* ret = new Server();
        if (Connect(ret, port) != RESULT_OK)
        {
            delete ret;
            return RESULT_SOCKET_ERROR;
        }

        ret->m_HttpRequest = params->m_HttpRequest;
        ret->m_Userdata = params->m_Userdata;
        ret->m_ConnectionTimeout = params->m_ConnectionTimeout * 1000000U;
        ret->m_Connections.SetCapacity(params->m_MaxConnections);

        *server = ret;
        return RESULT_OK;
    }

    void Delete(HServer server)
    {
        for (int32_t i; i < server->m_Connections.Size(); ++i)
        {
            dmSocket::Shutdown(server->m_Connections[i].m_Socket, dmSocket::SHUTDOWNTYPE_READWRITE);
            dmSocket::Delete(server->m_Connections[i].m_Socket);
            server->m_Connections[i].m_Socket = dmSocket::INVALID_SOCKET_HANDLE;
        }
        server->m_Connections.SetSize(0);
        dmSocket::Shutdown(server->m_ServerSocket, dmSocket::SHUTDOWNTYPE_READWRITE);
        dmSocket::Delete(server->m_ServerSocket);
        server->m_ServerSocket = dmSocket::INVALID_SOCKET_HANDLE;
        delete server;
    }

    /*
     * Handle an http-connection
     * Returns 0 - do nothing, 1 - remove, 2 - close.
     */
    static uint8_t HandleConnection(Server* server, Connection* connection)
    {
        int total_recv = 0;

        Request request;
        request.m_Result = RESULT_OK;
        request.m_Socket = connection->m_Socket;

        server->m_HttpRequest(server->m_Userdata, &request);

        if (request.m_Result == RESULT_OK)
        {
            if (request.m_RemoveConnection)
            {
                return 1;
            }
            else if (request.m_CloseConnection)
            {
                return 2;
            }
        }
        else
        {
            return 2;
        }
        return 0;
    }

    Result Update(HServer server)
    {
        if (server->m_Reconnect)
        {
            dmLogWarning("Reconnecting http server (%d)", server->m_Port);
            Connect(server, server->m_Port);
            server->m_Reconnect = 0;
        }
        dmSocket::Selector selector;
        dmSocket::SelectorSet(&selector, dmSocket::SELECTOR_KIND_READ, server->m_ServerSocket);

        dmSocket::Result r = dmSocket::Select(&selector, 0);

        if (r != dmSocket::RESULT_OK)
        {
            return RESULT_SOCKET_ERROR;
        }

        // Check for new connections
        if (dmSocket::SelectorIsSet(&selector, dmSocket::SELECTOR_KIND_READ, server->m_ServerSocket))
        {
            dmSocket::Address address;
            dmSocket::Socket client_socket;
            r = dmSocket::Accept(server->m_ServerSocket, &address, &client_socket);
            if (r == dmSocket::RESULT_OK)
            {
                if (server->m_Connections.Full())
                {
                    dmLogWarning("Out of client connections in http server (max: %d)", server->m_Connections.Capacity());
                    dmSocket::Shutdown(client_socket, dmSocket::SHUTDOWNTYPE_READWRITE);
                    dmSocket::Delete(client_socket);
                }
                else
                {
                    dmSocket::SetNoDelay(client_socket, true);
                    Connection connection;
                    memset(&connection, 0, sizeof(connection));
                    connection.m_Socket = client_socket;
                    connection.m_ConnectionTimeStart = dmTime::GetTime();
                    server->m_Connections.Push(connection);
                }
            }
            else if (r == dmSocket::RESULT_CONNABORTED || r == dmSocket::RESULT_NOTCONN)
            {
                server->m_Reconnect = 1;
            }
        }

        dmSocket::SelectorZero(&selector);

        uint64_t current_time = dmTime::GetTime();

        // Iterate over persistent connections, timeout phase
        for (uint32_t i = 0; i < server->m_Connections.Size(); ++i)
        {
            Connection* connection = &server->m_Connections[i];
            uint64_t time_diff = current_time - connection->m_ConnectionTimeStart;
            if (time_diff > server->m_ConnectionTimeout)
            {
                dmSocket::Shutdown(connection->m_Socket, dmSocket::SHUTDOWNTYPE_READWRITE);
                dmSocket::Delete(connection->m_Socket);
                connection->m_Socket = dmSocket::INVALID_SOCKET_HANDLE;
                server->m_Connections.EraseSwap(i);
                --i;
            }
        }

        // Iterate over persistent connections, select phase
        for (uint32_t i = 0; i < server->m_Connections.Size(); ++i)
        {
            Connection* connection = &server->m_Connections[i];
            dmSocket::SelectorSet(&selector, dmSocket::SELECTOR_KIND_READ, connection->m_Socket);
        }

        r = dmSocket::Select(&selector, 0);
        if (r != dmSocket::RESULT_OK)
            return RESULT_SOCKET_ERROR;

        // Iterate over persistent connections, handle phase
        for (uint32_t i = 0; i < server->m_Connections.Size(); ++i)
        {
            Connection* connection = &server->m_Connections[i];
            if (dmSocket::SelectorIsSet(&selector, dmSocket::SELECTOR_KIND_READ, connection->m_Socket))
            {
                uint8_t keep_connection = HandleConnection(server, connection);
                if (keep_connection == 1) // Remove
                {
                    server->m_Connections.EraseSwap(i);
                    --i;
                }
                else if (keep_connection == 2) // Close
                {
                    dmSocket::Shutdown(connection->m_Socket, dmSocket::SHUTDOWNTYPE_READWRITE);
                    dmSocket::Delete(connection->m_Socket);
                    connection->m_Socket = dmSocket::INVALID_SOCKET_HANDLE;
                    server->m_Connections.EraseSwap(i);
                    --i;
                }
            }
        }
        return RESULT_OK;
    }

    void GetName(HServer server, dmSocket::Address* address, uint16_t* port)
    {
        *address = server->m_Address;
        *port = server->m_Port;
    }
}
