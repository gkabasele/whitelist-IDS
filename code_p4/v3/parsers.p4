#include "headers.p4"


#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define IP_PROTOCOLS_SRTAG 200 
#define IP_PROTOCOLS_IDSTAG 201
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
        IP_PROTOCOLS_IDSTAG: parse_idstag;
        default: ingress; 
    }
}

parser parse_udp {
    extract(udp);
    //TODO check DNP protocols
    return ingress;
}

// Check if SYN is set
parser parse_tcp {
    extract(tcp);
    return select(latest.syn) {
       0x0 : parse_tcp_rst;
       default: ingress; 
    }
}

// Check if RST is set
parser parse_tcp_rst {
    return select(tcp.rst) {
        0x0 : parse_tcp_fin;
        default: ingress;
    }
}
// Check if FIN is set
parser parse_tcp_fin {
    return select(tcp.fin) {
       0x0 : parse_tcp_ack;
       default: ingress;
    }
}

// Check if ACK is set
parser parse_tcp_ack {
    return select(tcp.ack) {
       0x1 : parse_tcp_psh;
       default:  ingress; 
    }

}

// Check if PSH
parser parse_tcp_psh {
    return select(tcp.psh) {
        0x1 : parse_tcp_modbus;
        default: ingress;
    }
}


parser parse_tcp_modbus {
    return select(tcp.dstPort) {
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
    extract(srtag);
    return parse_tcp;
}

parser parse_idstag {
    extract(idstag);
    return parse_tcp;
}


