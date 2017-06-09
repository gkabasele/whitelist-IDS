#include "headers.p4"


#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define TCP_PORT_MODBUS 5020

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_ARP  : parse_arp;
        default: ingress;
    }
}

parser parse_arp {
    extract(arp);
    return ingress;
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
       IP_PROTOCOLS_TCP : parse_tcp;
       default: ingress; 
    }
}

parser parse_tcp {
    extract(tcp);
    return select(latest.dstPort) {
        TCP_PORT_MODBUS: parse_modbus;
        default: parse_modbus_dst;
    }
}

parser parse_modbus_dst {
    return select(tcp.srcPort) {
        TCP_PORT_MODBUS: parse_modbus;
        default: ingress;
    }
}


parser parse_modbus {
    extract(modbus);
    return parse_miss_tag;
}

parser parse_miss_tag {
    extract(miss_tag);
    return ingress;
}


