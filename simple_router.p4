/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

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
        dstAddr: 32;
    }
}

parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header ipv4_t ipv4;

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
        opt : 96;
    }
}

header tcp_t tcp;

header_type miss_tag_t {
    fields {
        value : 8;
    }
}

header miss_tag_t miss_tag;


header_type flow_meta_t {
    fields {
        flow_id : 16;
    }
}

metadata flow_meta_t flow_meta;

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

/*field_list flow_tuple_list {
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort;
    tcp.dstPort;
}

field_list_calculation flow_tuple {
    input {
        flow_tuple_list;
    }
    algorithm : csum16;
    output_width : 16;

}

register flow_id_register {
    width : 16;
    static : flow_id;
    instance_count: 50;
}
*/

#define IP_PROTOCOLS_TCP 6

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
       IP_PROTOCOLS_TCP : parse_tcp;
       default: ingress; 
    }
}

#define TCP_PORT_MODBUS 5020

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


action _drop() {
    drop();
}

header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
        flow_id : 16;
    }
}

metadata routing_metadata_t routing_metadata;

action set_nhop(nhop_ipv4, port) {
    modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
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

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
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

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
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

//Called by the parser
control ingress {
    if(valid(ipv4) and ipv4.ttl > 0) {
        apply(ipv4_lpm);
        // Check if tag header present
        if(valid(miss_tag)){
            apply(miss_tag_table);
        } else {
            apply(flow_id);
            if (tcp.dstPort == 5020 or tcp.srcPort == 5020){
                if(tcp.syn == 1 or tcp.fin == 1 or (tcp.ack == 1 and tcp.psh == 0)) {
                    //nothing to do here                
                } else {
                    apply(modbus);
                }
            }
        }
        apply(forward);
    }
}

//Called when the packet is dequeued
control egress {
    apply(send_frame);
}


