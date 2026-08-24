#include <gccore.h>
#include <network.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "tcp_gecko.h"

#define TG_MAGIC 0x5447 /* "TG" */

static s32 server_socket = -1;
static s32 client_socket = -1;
static bool initialized = false;

static tcp_gecko_cheat_t cheat_table[TG_MAX_CHEATS];
static u32 cheat_count = 0;

static u8 header_buffer[5];
static u8 payload_buffer[TG_MAX_PAYLOAD];

static u16 read_be16(const u8 *p)
{
    return ((u16)p[0] << 8) |
           ((u16)p[1]);
}

static u32 read_be32(const u8 *p)
{
    return ((u32)p[0] << 24) |
           ((u32)p[1] << 16) |
           ((u32)p[2] << 8) |
           ((u32)p[3]);
}

static void write_be16(u8 *p, u16 value)
{
    p[0] = (u8)(value >> 8);
    p[1] = (u8)value;
}

static void write_be32(u8 *p, u32 value)
{
    p[0] = (u8)(value >> 24);
    p[1] = (u8)(value >> 16);
    p[2] = (u8)(value >> 8);
    p[3] = (u8)value;
}

static void close_client(void)
{
    if (client_socket >= 0)
    {
        net_close(client_socket);
        client_socket = -1;
    }
}

static int send_all(const void *data, u32 length)
{
    const u8 *p = (const u8 *)data;
    u32 sent = 0;

    while (sent < length)
    {
        s32 ret = net_send(
            client_socket,
            p + sent,
            length - sent,
            0
        );

        if (ret <= 0)
        {
            close_client();
            return -1;
        }

        sent += ret;
    }

    return 0;
}

static int send_packet(
    u8 command,
    const void *payload,
    u16 length
)
{
    u8 header[5];

    write_be16(&header[0], TG_MAGIC);

    header[2] = command;

    write_be16(&header[3], length);

    if (send_all(header, sizeof(header)) < 0)
        return -1;

    if (length != 0 && payload != NULL)
        return send_all(payload, length);

    return 0;
}

static void send_ok(u8 original_command)
{
    u8 response[1];

    response[0] = original_command;

    send_packet(
        TG_RESP_OK,
        response,
        sizeof(response)
    );
}

static void send_error(
    u8 original_command,
    u8 error
)
{
    u8 response[2];

    response[0] = original_command;
    response[1] = error;

    send_packet(
        TG_RESP_ERROR,
        response,
        sizeof(response)
    );
}

static int validate_cheat_address(u32 address)
{
    /*
     * Restrict cheat records to the Wii's main MEM1 RAM.

     * This intentionally does NOT expose arbitrary address
     * access through the TCP service.
     */
    if (address < 0x80000000)
        return 0;

    if (address >= 0x81800000)
        return 0;

    return 1;
}

static void handle_cheat_upload(
    const u8 *payload,
    u16 length
)
{
    tcp_gecko_cheat_t cheat;

    /*
     * Wire format:

     * 0..3   address
     * 4..7   value
     * 8..11  mask
     * 12     type
     */

    if (length != 13)
    {
        send_error(
            TG_CMD_CHEAT_UPLOAD,
            1
        );
        return;
    }

    if (cheat_count >= TG_MAX_CHEATS)
    {
        send_error(
            TG_CMD_CHEAT_UPLOAD,
            2
        );
        return;
    }

    cheat.address = read_be32(&payload[0]);
    cheat.value   = read_be32(&payload[4]);
    cheat.mask    = read_be32(&payload[8]);
    cheat.type    = payload[12];

    if (!validate_cheat_address(
            cheat.address
        ))
    {
        send_error(
            TG_CMD_CHEAT_UPLOAD,
            3
        );
        return;
    }

    cheat_table[cheat_count] = cheat;

    cheat_count++;

    send_ok(TG_CMD_CHEAT_UPLOAD);
}

static void handle_packet(
    u8 command,
    const u8 *payload,
    u16 length
)
{
    u8 response[8];

    switch (command)
    {
        case TG_CMD_PING:
        {
            const char pong[] = "PONG";

            send_packet(
                TG_CMD_PING,
                pong,
                4
            );

            break;
        }

        case TG_CMD_VERSION:
        {
            write_be16(
                &response[0],
                1
            );

            write_be16(
                &response[2],
                TG_MAGIC
            );

            write_be16(
                &response[4],
                TCP_GECKO_PORT
            );

            send_packet(
                TG_CMD_VERSION,
                response,
                6
            );

            break;
        }

        case TG_CMD_STATUS:
        {
            response[0] = 1;

            write_be32(
                &response[1],
                cheat_count
            );

            send_packet(
                TG_CMD_STATUS,
                response,
                5
            );

            break;
        }

        case TG_CMD_CHEAT_UPLOAD:
        {
            handle_cheat_upload(
                payload,
                length
            );

            break;
        }

        case TG_CMD_CHEAT_CLEAR:
        {
            memset(
                cheat_table,
                0,
                sizeof(cheat_table)
            );

            cheat_count = 0;

            send_ok(
                TG_CMD_CHEAT_CLEAR
            );

            break;
        }

        case TG_CMD_CHEAT_COUNT:
        {
            write_be32(
                response,
                cheat_count
            );

            send_packet(
                TG_CMD_CHEAT_COUNT,
                response,
                4
            );

            break;
        }

        default:
        {
            send_error(
                command,
                0xFF
            );

            break;
        }
    }
}

static void accept_client(void)
{
    struct sockaddr_in client_address;
    socklen_t address_length;

    address_length =
        sizeof(client_address);

    client_socket = net_accept(
        server_socket,
        (struct sockaddr *)&client_address,
        &address_length
    );
}

static void receive_packet(void)
{
    s32 received;

    received = net_recv(
        client_socket,
        header_buffer,
        sizeof(header_buffer),
        MSG_WAITALL
    );

    if (received <= 0)
    {
        close_client();
        return;
    }

    if (received != sizeof(header_buffer))
    {
        close_client();
        return;
    }

    if (read_be16(
            &header_buffer[0]
        ) != TG_MAGIC)
    {
        close_client();
        return;
    }

    u8 command =
        header_buffer[2];

    u16 length =
        read_be16(
            &header_buffer[3]
        );

    if (length > TG_MAX_PAYLOAD)
    {
        close_client();
        return;
    }

    if (length > 0)
    {
        received = net_recv(
            client_socket,
            payload_buffer,
            length,
            MSG_WAITALL
        );

        if (received != length)
        {
            close_client();
            return;
        }
    }

    handle_packet(
        command,
        payload_buffer,
        length
    );
}

bool tcp_gecko_init(void)
{
    struct sockaddr_in address;

    if (initialized)
        return true;

    if_config(
        NULL,
        NULL,
        NULL,
        true,
        20
    );

    server_socket = net_socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_IP
    );

    if (server_socket < 0)
        return false;

    memset(
        &address,
        0,
        sizeof(address)
    );

    address.sin_family = AF_INET;
    address.sin_port =
        htons(TCP_GECKO_PORT);

    address.sin_addr.s_addr =
        htonl(INADDR_ANY);

    if (net_bind(
            server_socket,
            (struct sockaddr *)&address,
            sizeof(address)
        ) < 0)
    {
        net_close(server_socket);
        server_socket = -1;
        return false;
    }

    if (net_listen(
            server_socket,
            1
        ) < 0)
    {
        net_close(server_socket);
        server_socket = -1;
        return false;
    }

    initialized = true;

    return true;
}

void tcp_gecko_poll(void)
{
    if (!initialized)
        return;

    if (client_socket < 0)
    {
        accept_client();
        return;
    }

    receive_packet();
}

void tcp_gecko_shutdown(void)
{
    close_client();

    if (server_socket >= 0)
    {
        net_close(server_socket);
        server_socket = -1;
    }

    initialized = false;
}

u32 tcp_gecko_cheat_count(void)
{
    return cheat_count;
}

const tcp_gecko_cheat_t *
tcp_gecko_cheats(void)
{
    return cheat_table;
}
