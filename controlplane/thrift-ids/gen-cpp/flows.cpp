#include <boost/functional/hash_fwd.hpp>

#include "flows.h"

namespace ids
{
    bool operator==(flow const& a, flow const& b)
    {
        return ((a.src == b.src) &&
                (a.sport == b.sport) &&
                (a.proto == b.proto) &&
                (a.dst == b.dst) &&
                (a.dport == b.dport));
    }
    
    std::size_t hash_value(flow const& f)
    {
        std::size_t seed = 0;
        boost::hash_combine(seed, flow.src);
        boost::hash_combine(seed, flow.sport);
        boost::hash_combine(seed, flow.proto);
        boost::hash_combine(seed, flow.dst);
        boost::hash_combine(seed, flow.dport);

        return seed;
    }


}
