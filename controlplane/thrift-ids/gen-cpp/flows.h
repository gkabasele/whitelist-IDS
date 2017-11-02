#ifndef FLOW_H
#define FLOW_H

#include <linux/types.h>
#include <cstddef>

namespace ids
{
    struct flow
    {
       __u32    src;
       __u16    sport;
       __u8     proto;
       __u32    dst;
       __u16    dport;

        flow(__u32 s, __u16 sp, __u8 p, __u32 d, __u16 dp)
            : src(s), sport(sp), proto(p), dst(d), dport(dp) {}
        
    };
    
    bool operator==(flow const&, flow const&);
    std::size_t hash_value(flow const&);

}

#endif
