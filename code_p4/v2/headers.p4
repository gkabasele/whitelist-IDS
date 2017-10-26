header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header ethernet_t ethernet;

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr : 32;
        //opitons max 20 bytes
        options : *;
    }
    // length is expressed in bytes
    length : 4 * ihl;
    max_length : 60;
}

header ipv4_t ipv4;

header_type arp_t {
    fields {
        hwType : 16;
        protoType : 16;
        hwSize : 8;
        protoSize: 8;
        opcode : 16; // req or res 
        srcMac : 48;
        srcAddr : 32;
        dstMac : 48;
        dstAddr : 32;
    }
}

header arp_t arp;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
        ipv4.options;
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 3;
        ecn : 3;
        urg : 1;
        ack : 1;
        psh : 1;
        rst : 1;
        syn : 1;
        fin : 1;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
        //opt : 160;
        opt : *;
    }
    length : 4 * dataOffset;
    max_length :  60;
}

header tcp_t tcp;

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        len : 16;
        checksum : 16;
    }


}

header udp_t udp;

header_type srtag_t {
    fields {
        dstAddr : 32;   // original destination
        id : 16;        // id of the switch causing redirection
        proto : 8;      // original transport protocol 
        padding: 8;     // multiple value
    }
}

header srtag_t srtag;


header_type modbus_t {
    fields {
        transId: 16;
        proto: 16;
        len: 16;
        unitId: 8;
        funcode: 8;
    }
}

header modbus_t modbus;

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
        flow_id : 16;
    }
}
metadata routing_metadata_t routing_metadata;

header_type tmp_t {
    fields {
        ipAddr : 32;
        hwAddr : 48;
        is_dest: 1;
    }
}

metadata tmp_t tmp_arp;

header_type tmp_arp_t {
    fields {
        tmp_ipAddr : 32;
        tmp_hwAddr : 48;
        tmp_inport : 32;
        tmp_index : 8;
    }
}

metadata tmp_arp_t tmp_reg_arp;
