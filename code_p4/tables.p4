#include "parsers.p4"


action _drop() {
    drop();
}

action set_nhop(nhop_ipv4, port) {
    modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}


action _no_op() {
    no_op();
}

action respond_arp(dmac) {
    modify_field(tmp_arp.ipAddr, arp.dstAddr);
    modify_field(tmp_arp.hwAddr, arp.srcMac);

    modify_field(arp.dstMac, arp.srcMac);
    modify_field(arp.dstAddr, arp.srcAddr);

    modify_field(arp.srcMac, dmac);
    modify_field(arp.srcAddr, tmp_arp.ipAddr);

    modify_field(standard_metadata.egress_spec, standard_metadata.ingress_port);
}

action add_miss_tag(value, egress_port) {
    add_header(miss_tag);
    // Change protocol to specify presence of tag
    modify_field(ipv4.protocol, 0x00c8);

    // Set type of tag
    modify_field(miss_tag.value, value);
    
    // Set egress port to reach IDS
    modify_field(standard_metadata.egress_spec, egress_port);
}

action redirect_packet(egress_port) {
    modify_field(standard_metadata.egress_spec, egress_port);
}

action add_expected_port(sport, dport) {
    modify_field(flow_meta.dstAddr, ipv4.dstAddr);
    modify_field(flow_meta.srcAddr, ipv4.srcAddr);
    modify_field(flow_meta.expected_sport, sport);
    modify_field(flow_meta.expected_dport, dport);
}

table arp_response {
    reads {
        arp.dstAddr : exact;
    }
    actions {
        respond_arp;
        _drop;
    }
}


table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
        _no_op;
    }
    size: 1024;
}



table forward {
    reads {
        routing_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
        _no_op;
    }
    size: 512;
}



table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}



table flow_id {
    reads {
        ipv4.srcAddr : exact;
        ipv4.dstAddr : exact;
        ipv4.protocol : exact;
       // tcp.srcPort : exact;
       // tcp.dstPort : exact;
    }
    actions {
        _drop;
        _no_op;
        add_miss_tag;
        add_expected_port;
    }
    size : 100;
}

// table for expected port given ip addresses
table ex_port {
    reads {
        flow_meta.srcAddr : exact;
        flow_meta.dstAddr : exact;
        flow_meta.expected_sport: exact;
        flow_meta.expected_dport: exact;
    }
    actions {
        _drop;
        _no_op;
        add_miss_tag;
    }
    size: 100;
}


table modbus {
    reads {
        ipv4.srcAddr : exact;
        ipv4.dstAddr : exact;
        modbus.funcode: exact;
    }
    actions {
        _drop;
        _no_op;
        add_miss_tag;
    }
    size : 100;
}

table miss_tag_table {
    reads {
        miss_tag.value : exact;
    }
    actions {
        _drop;
        redirect_packet;
    }
}
