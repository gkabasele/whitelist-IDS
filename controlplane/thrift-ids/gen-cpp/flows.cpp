#include <boost/functional/hash.hpp>

#include "flows.h"

namespace ids
{
    bool operator==(flow const& a, flow const& b) const
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
        boost::hash_combine(seed, f.src);
        boost::hash_combine(seed, f.sport);
        boost::hash_combine(seed, f.proto);
        boost::hash_combine(seed, f.dst);
        boost::hash_combine(seed, f.dport);

        return seed;
    }


}
