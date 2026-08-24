#ifndef __TCP_GECKO_H__
#define __TCP_GECKO_H__

#include <gccore.h>

#define TCP_GECKO_PORT 7331

#define TG_CMD_PING          0x01
#define TG_CMD_VERSION       0x02
#define TG_CMD_STATUS        0x03

#define TG_CMD_CHEAT_UPLOAD  0x20
#define TG_CMD_CHEAT_CLEAR   0x21
#define TG_CMD_CHEAT_COUNT   0x22

#define TG_RESP_OK           0x80
#define TG_RESP_ERROR        0x81

#define TG_MAX_PAYLOAD       1024
#define TG_MAX_CHEATS        128

typedef struct
{
    u32 address;
    u32 value;
    u32 mask;
    u8  type;
} tcp_gecko_cheat_t;

bool tcp_gecko_init(void);
void tcp_gecko_poll(void);
void tcp_gecko_shutdown(void);

u32 tcp_gecko_cheat_count(void);
const tcp_gecko_cheat_t *tcp_gecko_cheats(void);

#endif
