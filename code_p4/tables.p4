#include "parsers.p4"


action _drop() {
    drop();
}

action set_egress_port(port) {
  //  modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
  //  add_to_field(ipv4.ttl, -1);
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

    // Set opcode to reply 
    modify_field(arp.opcode, 2);

    modify_field(ethernet.srcAddr, dmac);
    modify_field(ethernet.dstAddr, tmp_arp.hwAddr);
    modify_field(standard_metadata.egress_spec, standard_metadata.ingress_port);
    
    // Switch is queried no need to forward
    modify_field(tmp_arp.is_dest, 1);
}


action add_miss_tag(reason, id, ids_addr, egress_port) {
    add_header(srtag);

    // Set type of tag
    modify_field(srtag.reason, reason);
    modify_field(srtag.id, id);
    modify_field(srtag.dstAddr, ipv4.dstAddr);
    modify_field(srtag.proto, ipv4.protocol);

    // Change protocol to specify presence of tag
    modify_field(ipv4.protocol, 0x00c8);

    // Change total length of ip 
    add_to_field(ipv4.totalLen, 8); 

        
    // Setting IDS ip
    modify_field(ipv4.dstAddr, ids_addr);

    // Setting egress port to reach IDS
    modify_field(standard_metadata.egress_spec, egress_port);
}

action redirect_packet(egress_port) {
    modify_field(standard_metadata.egress_spec, egress_port);
}




register arp_ip {
    width : 32;
    instance_count : 256;
}

register arp_mac {
    width : 48;
    instance_count : 256;
}

register arp_in_port {
    width : 32;
    instance_count : 256;
}

register arp_index {
    width : 32;
    instance_count : 1;
} 

action store_arp_in(egress_port){
    register_read(tmp_reg_arp.tmp_index, arp_index, 0);
    register_write(arp_ip, tmp_reg_arp.tmp_index, arp.srcAddr);
    register_write(arp_mac, tmp_reg_arp.tmp_index, arp.srcMac);
    register_write(arp_in_port, tmp_reg_arp.tmp_index, standard_metadata.ingress_port);
    //add_to_field(tmp_reg_arp.tmp_index, 1);
    modify_field(standard_metadata.egress_spec, egress_port);
}

action forward_arp() {
    register_read(tmp_reg_arp.tmp_index, arp_index, 0);
    register_read(tmp_reg_arp.tmp_inport, arp_in_port, tmp_reg_arp.tmp_index);
    modify_field(standard_metadata.egress_spec, tmp_reg_arp.tmp_inport);
}


table arp_response {
    reads {
        arp.dstAddr : exact;
        arp.opcode : exact;
    }
    actions {
        respond_arp;
        _no_op;
    }
}

table arp_forward_req {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        store_arp_in;
        _drop;
    }
}

table arp_forward_resp {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        forward_arp;
        _drop;
    }
}


table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_egress_port;
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
        _no_op;
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
    }
    size : 100;
}

// table for expected port given ip addresses
table ex_port {
    reads {
        ipv4.srcAddr : exact;
        ipv4.dstAddr : exact;
        tcp.srcPort  : exact;
        tcp.dstPort : exact ;
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
        ipv4.srcAddr: exact;
        tcp.srcPort: exact;
        modbus.funcode: exact;
    }
    actions {
        _drop;
        _no_op;
        add_miss_tag;
    }
    size : 100;
}

table modbus_payload_size {
    reads {
        ipv4.srcAddr: exact;
        tcp.srcPort: exact;
        modbus.funcode: exact;
        standard_metadata.packet_length: exact;
    }
    actions {
        _drop;
        _no_op;
        add_miss_tag;
    }
}

table miss_tag_table {
    reads {
        srtag.reason : exact;
    }
    actions {
        _drop;
        redirect_packet;
    }
}
