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

//action compute_flow_id(base, nport) {
//    modify_field_with_hash_based_offset(flow_meta.flow_id,base,flow_tuple,nport);
//}

action _no_op() {
    no_op();
}

action add_miss_tag(value, egress_port) {
    add_header(miss_tag);

    // Set type of tag
    modify_field(miss_tag.value, value);
    
    // Set egress port to reach IDS
    modify_field(standard_metadata.egress_spec, egress_port);
}

action redirect_packet(egress_port) {
    modify_field(standard_metadata.egress_spec, egress_port);
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
        //tcp.srcPort : exact;
        //tcp.dstPort : exact;
    }
    actions {
        _drop;
        _no_op;
        add_miss_tag;
        //compute_flow_id;
    }
    size : 100;
}

table modbus {
    reads {
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
