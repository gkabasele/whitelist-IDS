/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_SRTAG = 0xC8; //200
const bit<8> TYPE_IDSTAG = 0xC9; //201
const bit<8>  TYPE_TCP = 0x06;

const bit<32> BMV2_V1_MODEL_INSTANCE_TYPE_INGRESS_CLONE=1;
const bit<32> BMV2_V1_MODEL_INSTANCE_TYPE_RESUBMIT=6;
const bit<32> I2E_CLONE_SESSION_ID = 5;

#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1_MODEL_INSTANCE_TYPE_INGRESS_CLONE)
#define IS_RESUBMITTED(std_meta) (std_meta.instance_type == BMV2_V1_MODEL_INSTANCE_TYPE_RESUBMIT)

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srtag_t {
    bit<32> origAddr;    // original destination
    bit<16> switch_id;  // id of the switch causing redirection
    bit<8>  proto;      // original transport protocol
    bit<8>  padding;    //padding
 }

header idstag_t {
    bit<16> val;        // value set by the IDS to specify that the packet has been inspected
    bit<8> proto;       // original transport protocol
    bit<8> padding;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
    // options
    // lenght : 4 * ihl;
}

header tcp_t {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<32> seqNo;
	bit<32> ackNo;
	bit<4>  dataOffset;
	bit<3>	res;
	bit<3>	ecn;
    // flags 6bit
	bit<1>	urg;
	bit<1>	ack;
	bit<1>	psh;
	bit<1>	rst;
	bit<1>	syn;
	bit<1>	fin;
	bit<16>	window;
	bit<16>	checksum;
	bit<16> urgentPtr;
}

struct metadata {
    bit<1> isRetrans;
    bit<1> isTerminated;
    bit<1> markForIDS; // flag to identify miss flow
    bit<1> ignoreIP;
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    idstag_t     idstag;
    srtag_t      srtag;
    ipv4_t       ipv4;
	tcp_t		 tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
	    	TYPE_IPV4: parse_ipv4;
        	default: accept;
		}
    }

    state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			TYPE_TCP: parse_tcp;
            TYPE_SRTAG: parse_srtag;
            TYPE_IDSTAG: parse_idstag;
			default: accept;
		}
    }


    state parse_srtag {
        packet.extract(hdr.srtag);
        transition select(hdr.srtag.proto) {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_idstag {
        packet.extract(hdr.idstag);
        transition select(hdr.idstag.proto){
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

	state parse_tcp {
		packet.extract(hdr.tcp);
		transition accept;
	}
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

	// Registers for seq and retransmission
	register<bit<32>>(1024) curSeqno;
    register<bit<16>>(1024) curlen;
	counter(1024, CounterType.packets_and_bytes) ingressPktStats;
    counter(1024, CounterType.packets) retransCount;
    counter(1024, CounterType.packets) terminatedCount;

	action update_stats(bit<32> flow_id) {
		ingressPktStats.count(flow_id);
		bit<32> last_seqno;
        bit<16> last_len;
		bit<16> packet_length;
		bit<16> tcp_len = (bit<16>) hdr.tcp.dataOffset;
		curSeqno.read(last_seqno, flow_id);
        curlen.read(last_len, flow_id);
		packet_length = hdr.ipv4.totalLen - (20 + 4*tcp_len);
        meta.isRetrans = 0;
		if ((last_seqno == hdr.tcp.seqNo && packet_length > 0 && last_len > 0)|| last_seqno > hdr.tcp.seqNo){
			meta.isRetrans = 1;
		} else {
			meta.isRetrans = 0;
		}
		curSeqno.write(flow_id, hdr.tcp.seqNo);	
        curlen.write(flow_id, packet_length);

        meta.isTerminated = (hdr.tcp.rst | hdr.tcp.fin);
	}

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action update_retrans_counter(bit<32> flow_id) {
        retransCount.count(flow_id);
        //clone3(CloneType.I2E, I2E_CLONE_SESSION_ID, standard_metadata);
        clone(CloneType.I2E, I2E_CLONE_SESSION_ID);
        meta.isRetrans = 0;
    }

    action update_terminated_counter(bit<32> flow_id) {
        terminatedCount.count(flow_id);
        //clone3(CloneType.I2E, I2E_CLONE_SESSION_ID, standard_metadata);
        clone(CloneType.I2E, I2E_CLONE_SESSION_ID);
        meta.isTerminated = 0;
    }

    action mark_for_ids(){
        meta.markForIDS = 1;
    }

    action add_miss_tag(bit<16> switch_id, bit<32> ids_addr, egressSpec_t port) {

        //Adding the header is done in the deparser, you need to set valid first
        hdr.srtag.setValid();

        hdr.srtag.switch_id = switch_id;
        hdr.srtag.origAddr = hdr.ipv4.dstAddr;
        hdr.srtag.proto = hdr.ipv4.protocol;
        hdr.srtag.padding = 0;
        
        // increment length by the size of the tag
        hdr.ipv4.protocol = TYPE_SRTAG;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
        hdr.ipv4.dstAddr = ids_addr;

        standard_metadata.egress_spec = port; 
        meta.markForIDS = 0;
    }

    action add_ids_tag( bit<16> val){
        hdr.idstag.setValid();
        hdr.idstag.proto = hdr.ipv4.protocol;
        hdr.idstag.val = val;
        hdr.idstag.padding = 0;
        hdr.ipv4.protocol  = TYPE_IDSTAG;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    }

    action remove_ids_tag(){
        hdr.ipv4.protocol = hdr.idstag.proto;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 4;
        hdr.idstag.setInvalid();
    }

    action remove_miss_tag(macAddr_t dstAddr, egressSpec_t port){
        meta.ignoreIP = 1;
        hdr.ipv4.dstAddr = hdr.srtag.origAddr;
        hdr.ipv4.protocol = hdr.srtag.proto;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 8;
        standard_metadata.egress_spec = port; 
        macAddr_t tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.srcAddr = tmp; 
        hdr.ethernet.dstAddr = dstAddr;
        hdr.srtag.setInvalid();
    }

    action change_to_ip_and_forward(macAddr_t dstAddr, egressSpec_t port){
        macAddr_t tmp;
        standard_metadata.egress_spec = port;
        hdr.ethernet.etherType = TYPE_IPV4;
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.srcAddr = tmp;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        /* TODO: fill out code in action body */
        if (meta.ignoreIP == 0){
            standard_metadata.egress_spec = port;
	        macAddr_t tmp;
	        tmp = hdr.ethernet.dstAddr;
	        hdr.ethernet.dstAddr = dstAddr;
	        hdr.ethernet.srcAddr = tmp;
        }
	    hdr.ipv4.ttl = hdr.ipv4.ttl-1;
        meta.ignoreIP = 0;
    }

    action clone_for_ids() {
        clone(CloneType.I2E, I2E_CLONE_SESSION_ID);
    }

    action do_nothing(){
        //Do nothing
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

	table flow_exact {
		key = {
			hdr.ipv4.srcAddr: exact;
			hdr.tcp.srcPort: exact;
			hdr.ipv4.dstAddr: exact;
			hdr.tcp.dstPort: exact;
			hdr.ipv4.protocol: exact;
		}
		actions = {
			update_stats;
			drop;
            mark_for_ids;
            //change_to_srtag;
		}
		size = 1024;
		default_action = mark_for_ids();
	}

    table srtag_exact {
        key = {
            hdr.ipv4.protocol: exact;  
            hdr.ipv4.dstAddr: exact; // remove tag if the swith is close to destination
        }
        actions = {
            //srtag_forward;
            remove_miss_tag;
            //change_to_ip_and_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table ids_verification { // Swith connected to IDS which add nonce
        key = {
            standard_metadata.ingress_port: exact;
            //hdr.ipv4.dstAddr : exact;
        }
        actions = {
            add_ids_tag;
            //change_to_srtag_ids;
            NoAction;
        }
        size = 16;
        default_action = NoAction();
    }

    table ids_clear{
        key = {
            hdr.ipv4.protocol: exact;
            hdr.idstag.val: exact;
            hdr.ipv4.dstAddr: exact;// remove tag if the swith is close to destination
            //standard_metadata.ingress_port: exact;
        }
        actions = {
            remove_ids_tag; 
            NoAction;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table marked_flows{
        key = {
            meta.markForIDS: exact;
        }
        actions = {
            NoAction;
            add_miss_tag;
        }
        default_action = NoAction();
    }

    table metaRetrans_exact {
        key = {
            meta.isRetrans: exact;
			hdr.ipv4.srcAddr: exact;
			hdr.tcp.srcPort: exact;
			hdr.ipv4.dstAddr: exact;
			hdr.tcp.dstPort: exact;
			hdr.ipv4.protocol: exact;
        }
        actions = {
            update_retrans_counter;
            NoAction;
        }
        default_action = NoAction();
    }

    table metaTermination_exact {
        key = {
            meta.isTerminated: exact;
			hdr.ipv4.srcAddr: exact;
			hdr.tcp.srcPort: exact;
			hdr.ipv4.dstAddr: exact;
			hdr.tcp.dstPort: exact;
			hdr.ipv4.protocol: exact;
        }
        actions = {
            update_terminated_counter;
            NoAction;
        }
        default_action = NoAction();
    }
    

    table backup_init_flow_exact {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            NoAction;
            clone_for_ids;
            do_nothing;
        }
        size = 1024;
        default_action = NoAction();
    }

    table backup_flow_exact {
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.tcp.srcPort: exact;
        }
        actions = {
            NoAction;
            do_nothing;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
   
        /* TODO: fix ingress control logic
         *  - ipv4_lpm should be applied only when IPv4 header is valid
         */
        
        if (backup_init_flow_exact.apply().hit ||
            backup_flow_exact.apply().hit){
            if(hdr.ipv4.protocol == TYPE_IDSTAG){
                ids_clear.apply(); 
            }
            // PASS
        } else if (!(ids_verification.apply().hit)){
                  if (hdr.ipv4.protocol == TYPE_IDSTAG){
                      ids_clear.apply();
                  } else if (hdr.ipv4.protocol == TYPE_SRTAG){
                      srtag_exact.apply();
                  } else if(hdr.tcp.isValid()){
		                  if (flow_exact.apply().hit) {
                              metaRetrans_exact.apply();
                              metaTermination_exact.apply();
                          }
                          marked_flows.apply();
                  }
        }

        if (hdr.ipv4.isValid()){
            ipv4_lpm.apply();     
        }
   }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action add_miss_tag(bit<16> switch_id, bit<32> ids_addr, egressSpec_t port) {

        //Adding the header is done in the deparser, you need to set valid first
        hdr.srtag.setValid();

        hdr.srtag.switch_id = switch_id;
        hdr.srtag.origAddr = hdr.ipv4.dstAddr;
        hdr.srtag.proto = hdr.ipv4.protocol;
        hdr.srtag.padding = 0;
        
        // increment length by the size of the tag
        hdr.ipv4.protocol = TYPE_SRTAG;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
        hdr.ipv4.dstAddr = ids_addr;

        standard_metadata.egress_spec = port; 
        meta.markForIDS = 0;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }


    // Special packets are cloned to keep track of connection 
    table clone_exact {
        key = {
            hdr.ipv4.srcAddr : exact;
        }
        actions = {
           drop;
           //change_to_srtag; 
           add_miss_tag;
        }
        size = 1024;
        default_action = drop();
    }


    apply { 
        if (IS_I2E_CLONE(standard_metadata)){
            clone_exact.apply();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: add deparser logic */
	packet.emit(hdr.ethernet);
	packet.emit(hdr.ipv4);
    packet.emit(hdr.srtag);
    packet.emit(hdr.idstag); // emit serializes header if valid
	packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
