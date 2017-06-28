#include "headers.p4"


#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define IP_PROTOCOLS_SRTAG 200 
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
        IP_PROTOCOLS_UDP : parse_udp; 
        IP_PROTOCOLS_SRTAG: parse_srtag;
        default: ingress; 
    }
}

parser parse_udp {
    extract(udp);
    //TODO check DNP protocols
    return ingress;
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
    return ingress;
}

parser parse_srtag {
    extract(tcp);
    extract(srtag);
    return ingress;
}


