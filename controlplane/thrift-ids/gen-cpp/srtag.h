#ifndef SRTAG_H
#define SRTAG_H

#include <linux/types.h>

#define IPPROTO_SRTAG 200

#define SRTAG_MISS 0
#define SRTAG_CLON 1

struct srtag_hdr {
        __u32   dest;
        __u16   identifier;
        __u8    protocol;
        __u8    reason;
};

#endif
