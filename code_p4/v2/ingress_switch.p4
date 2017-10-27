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

#include "tables.p4"

//Called by the parser
control ingress {
    if(valid(ipv4) and ipv4.ttl > 0) {
        apply(ipv4_lpm);
        // Check if tag header present
        if(ipv4.protocol == 0x00c8){
            //TODO set cookie to authenticate p4 switch
            //nothing to do here
        } else {
            if(ipv4.protocol == 0x0006 and (tcp.fin == 1 or tcp.rst == 1 )){
                apply(tcp_flags);
            }
            apply(flow_id){
                hit{
                    if (ipv4.protocol == 0x0006 and (tcp.dstPort == 5020 or tcp.srcPort == 5020)){
                        if(tcp.syn == 1 or tcp.fin == 1 or (tcp.ack == 1 and tcp.psh == 0)) {
                            //nothing to do here                
                        } else {
                            apply(modbus);                                      
                        }
                    }
                }
            }
        }
        apply(forward);
    } else if (valid(arp)) {
        apply(arp_response);
        if(tmp_arp.is_dest == 0){
            // Request
            if(arp.opcode == 1) {
               apply(arp_forward_req); 
            } else if (arp.opcode == 2) {
               apply(arp_forward_resp); 
            } else {
               //nothing to do here
            }
        }
    }
}

//Called when the packet is dequeued
control egress {
    apply(pkt_cloned);
    apply(send_frame);
}


