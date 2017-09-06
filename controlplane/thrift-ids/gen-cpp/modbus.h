#include <linux/types.h>

struct modbus_hdr {
    __u16       transId;
    __u16       protoId;
    __u16       len;
    __u8        unitId;
    __u8        funcode;
};

