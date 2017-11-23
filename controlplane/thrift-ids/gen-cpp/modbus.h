#ifndef MODBUS_H
#define MODBUS_H

#include <linux/types.h>

#define MODBUS_PORT 5020

struct modbus_hdr {
    __u16       transId;
    __u16       protoId;
    __u16       len;
    __u8        unitId;
    __u8        funcode;
};

struct modbus_diag_hdr {
    __u16       subfuncode;
};

#endif
