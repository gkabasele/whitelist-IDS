#include <iostream>
#include <vector>
#include <cstdio> 
#include <cstdlib>
#include <cstdint>
#include <unordered_map>

/* Netfilter queue */
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* Libcrafter */
#include <crafter.h>
#include <crafter/Utils/TCPConnection.h>


/* Thrift */
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/protocol/TBinaryProtocol.h>

/* HashMap*/

#include <boost/unordered_map.hpp>
#include <boost/functional/hash_fwd.hpp>

/* Utils */

#include "Controller.h"
#include "Controller_Client.h"
#include "srtag.h"
#include "modbus.h"
#include "flows.h"

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

using namespace IDSControllerCpp;


// Initialize client
boost::shared_ptr<TSocket> tsocket(new TSocket("172.0.10.2", 2050));
boost::shared_ptr<TTransport> ttransport(new TBufferedTransport(tsocket));
boost::shared_ptr<TProtocol> tprotocol(new TBinaryProtocol(ttransport)); 

ControllerClient client(tprotocol); 

boost::unordered_map<std::size_t, int> flow_map;

/* Convert u32 to an string ipv4 address */

std::string to_ipv4_string(__u32 ip)
{
    unsigned char bytes[4];
    char buffer [16];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(buffer,"%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return std::string(buffer);
}

// TODO check if packet is malicious

/* */
void handle_tcp_pkt(struct iphdr* ip_info,struct srtag_hdr *srtag_info, 
                    std::vector<int16_t> switches, unsigned char* data, int ret)

{
    struct tcphdr *tcp_info;
    struct modbus_hdr *modbus_info = NULL;
    struct sockaddr_in connection;
    int sockfd;
    int optval = 1;
    Flow req;
    unsigned int index;

    std::string srcip = to_ipv4_string(ip_info->saddr);
    std::string dstip = to_ipv4_string(srtag_info->dest); 
    int8_t proto = (int8_t)(srtag_info->protocol);

    /*Get TCP header*/
    index = (ip_info->ihl*4) + sizeof(*srtag_info);
    tcp_info = (struct tcphdr*) (data + index);
    /*TODO check for oveflow ?*/
    int16_t srcport = (int16_t) ntohs(tcp_info->source);
    int16_t dstport = (int16_t) ntohs(tcp_info->dest);
    //int32_t l_sport = (int32_t) ntohs(tcp_info->source);
    //int32_t l_dport = (int32_t) ntohs(tcp_info->dest);
    req = form_request(srcip, dstip, srcport, dstport, proto);

    /* Get TCP header options */
    if (is_modbus_pkt(tcp_info)) { 
        index += (tcp_info->doff*4);
        modbus_info = (struct modbus_hdr*) (data + index);                
        /* TODO check if int is too big for short values*/
        int8_t funcode = (int8_t) modbus_info->funcode;
        int16_t length = (int16_t) ret;
        printf("Modbus Pkt: funcode = %d\n", funcode);
        req.__set_length(length);
        req.__set_funcode(funcode); 
    }
    switches.push_back((int16_t) srtag_info->identifier);
    if (tcp_info-> rst == 1){ 
        printf("Received RST pkt\n");
        client.remove(req, switches);
        req = form_request(dstip, srcip, dstport, srcport, proto);
        client.remove(req, switches); 
    } else if (tcp_info->fin == 1) {
        printf("Received FIN pkt\n");
        ids::flow flow_info = ids::flow(ip_info->saddr, tcp_info->source, srtag_info->protocol,
                                  srtag_info->dest, tcp_info->dest); 
        boost::hash<ids::flow> flow_hasher;
        std::size_t flow_id = flow_hasher(flow_info);
        flow_map[flow_id] = 1;        
    } else if (tcp_info->ack == 1 && tcp_info->fin == 0 && tcp_info->psh==0){
        printf("Received ACK pkt\n");
        ids::flow flow_info = ids::flow(ip_info->saddr, tcp_info->source, srtag_info->protocol,
                                  srtag_info->dest, tcp_info->dest); 
        if (con_term(flow_map, flow_info)){
            client.remove(req, switches);
            req = form_request(dstip, srcip, dstport, srcport, proto);
            client.remove(req, switches);
        } 
    } else {
        client.allow(req, switches); 
    }
    /* Forge packet */
    ip_info->daddr = srtag_info->dest;
    ip_info->protocol = srtag_info->protocol;
    ip_info->tot_len = ip_info->tot_len - sizeof(*srtag_info);
    ip_info->check = in_cksum((unsigned short*) ip_info, sizeof(ip_info));

    /* Copy packet */
    unsigned char* crafted_packet; 
    unsigned int length = ret - sizeof(*srtag_info);  
    crafted_packet = forge_packet(length, ip_info, srtag_info, tcp_info,
                                  modbus_info);

    /* Send packet */                
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* IP_HDRINCL no default ip set by the kernel */
    if ((setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int))) < 0){
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    connection.sin_family = AF_INET;
    connection.sin_addr.s_addr = inet_addr(dstip.c_str());

    /* Forwarding packet */
    if (sendto(sockfd, crafted_packet, length, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr)) < 0){
        perror("sendto");
        exit(EXIT_FAILURE);
    } 
    close(sockfd);
    free(crafted_packet);
}


bool con_term(boost::unordered_map<std::size_t, int> hashmap , ids::flow flow_info)
{
    /* Check if FIN packet has been sent by each endpoint*/
    ids::flow comp_flow = ids::flow(flow_info.dst, flow_info.dport, flow_info.proto, flow_info.src, flow_info.sport);
    boost::hash<ids::flow> flow_hasher;
    std::size_t flow_id_a = flow_hasher(flow_info);
    std::size_t flow_id_b = flow_hasher(comp_flow);
    
    return (hashmap.find(flow_id_a) != hashmap.end() &&
            hashmap.find(flow_id_b) != hashmap.end());
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    //u_int32_t mark,ifi; 
    int ret;
    struct iphdr *ip_info;
    struct tcphdr *tcp_info;
    struct srtag_hdr *srtag_info;
    std::vector<int16_t> switches;
    Flow req;
    
    
    //struct sockaddr_in connection;
    //int sockfd;
    //int optval;
    
    unsigned char *data;

    // return header of the netlink packet    
    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
            id = ntohl(ph->packet_id);
            printf("hw_protocol=0x%04x hook=%u id=%u ",
                    ntohs(ph->hw_protocol), ph->hook, id);
    }
    // Retrieves the hardware address associated with the given queued packet. 
    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
            int i, hlen = ntohs(hwph->hw_addrlen);
            printf("hw_src_addr=");
            for (i = 0; i < hlen-1; i++)
                    printf("%02x:", hwph->hw_addr[i]);
            printf("%02x ", hwph->hw_addr[hlen-1]);
    }
   
    /* Return the netfilet mark currently assiged to the given queued packet 
    mark = nfq_get_nfmark(tb);
    if (mark)
            printf("mark=%u ", mark);*/
    
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
            printf("payload_len=%d ", ret);
            ip_info  = (struct iphdr *) data;
            printf("IP : src = %u , dest = %u\n " , ip_info->saddr, ip_info->daddr);
            std::string srcip = to_ipv4_string(ip_info->saddr);
            switch(ip_info->protocol) {
                case IPPROTO_SRTAG: 
                {
                    srtag_info = (struct srtag_hdr*) (data + (ip_info->ihl*4));
                    std::string dstip = to_ipv4_string(srtag_info->dest); 
                    int8_t proto = (int8_t)(srtag_info->protocol);
                    switch(proto) {
                        case IPPROTO_TCP:
                        {
                            handle_tcp_pkt(ip_info, srtag_info, switches, data, ret);
                            break;

                        }                        
                        case IPPROTO_UDP:
                        {
                            printf("UDP packet");
                            break;
                        }                         
                        default:
                        {
                            printf("Unknown protocol");
                            break;
                        }
                    }
                }
                case IPPROTO_TCP:
                {    
                    tcp_info = (struct tcphdr*) (data + sizeof(*ip_info));
                    unsigned short dest_port = ntohs(tcp_info->dest);
                    printf("TCP : dest = %d", dest_port);
                }   break;
                default:
                {
                    printf("Unknown protocol");
                    break;
                }
            }
      }
    
    
    fputc('\n', stdout);
    
    return id;
}

unsigned short in_cksum(unsigned short *addr, int len)
{
    /* Divide the IP header in 16 bits word and sum each of them
    
    */

    /* store that variable in processor register*/
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer; 
    }
    /* add hi 16 to low 16 */
    sum = (sum >> 16) + (sum & 0xffff); 
    /* add carry */
    sum += (sum >> 16);
    /* truncate to 16 bits */
    answer = ~sum;
    return (answer);
}

// Strip srtag to get original packet
unsigned char* forge_packet(unsigned int length, struct iphdr* ip_info, struct srtag_hdr* srtag_info, 
                            struct tcphdr* tcp_info, struct modbus_hdr* modbus_info)
{
    unsigned char* forged_packet = (unsigned char*) malloc(length);
    if (forged_packet == NULL)
    {
        exit(1);
    }

    unsigned int remaining_len = length;
    unsigned int iph_len = ip_info->ihl*4;
    unsigned int tcph_len = tcp_info->doff*4;
    if (remaining_len >= sizeof(*ip_info))
    {
        std::memcpy(forged_packet, ip_info, iph_len); 
        //struct iphdr* ip_inv = (struct iphdr*) (forged_packet);
        //ip_inv-> daddr = srtag_info->dest;
        //ip_inv-> tot_len = length;
        remaining_len = remaining_len - iph_len;
    } else {
        exit(1);
    }
    
    if (remaining_len >= sizeof(*tcp_info))
    {
        std::memcpy(forged_packet+iph_len, tcp_info, tcph_len);
        remaining_len = remaining_len - tcph_len;
    } else {
        exit(1); 
    }

    if (remaining_len >= sizeof(*modbus_info) && modbus_info != NULL)
    {
        std::memcpy(forged_packet+sizeof(*ip_info)+sizeof(*tcp_info), modbus_info, sizeof(*modbus_info)); 
    } 

    return forged_packet; 
}

// Detecting if the packet is a modbus packet
bool is_modbus_pkt(struct tcphdr* tcp_info)
{
    return ((tcp_info->psh == 1 && tcp_info->ack == 1)  && 
            (ntohs(tcp_info->source) == MODBUS_PORT || ntohs(tcp_info->dest) == MODBUS_PORT));
}

// Create a request to the controller
Flow form_request(std::string srcip, std::string dstip, 
                  int16_t srcport, int16_t dstport, int8_t proto)
{
    Flow req ;
    // Set argument of flow request 
    req.srcip = srcip; 
    req.dstip = dstip;
    req.srcport = srcport;
    req.dstport = dstport;
    req.proto = proto;
    return req;
}

void treat_pkt(char* data, int* verdict)
{
    // Retrieve value from packet
    
    // Analyze packet to form request
    
    // Send to request to controller 

    // Modify packet and forward if necessary

    // Drop packet
}


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data)
{
    //int verdict;
    u_int32_t id = print_pkt(nfa);

    //treat_pkt(nfa, &verdict);  Send request to controller
    //return nfq_set_verdict(qh, id, verdict, 0, NULL);  Verdict packet
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
        

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    //struct nfnl_handle *nh;
    int fd;
    int rv;
    // TODO: what happens if packet too big
    char buf[4096] __attribute__ ((aligned));

    

    // NFQUEUE packet capture of packet
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
            fprintf(stderr, "error during nfq_open()\n");
            exit(1);
    }

    
    //obsolete since kernel 3.8
    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
            fprintf(stderr, "error during nfq_unbind_pf()\n");
            exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
            fprintf(stderr, "error during nfq_bind_pf()\n");
            exit(1);
    }

    // Last argument, some data to pass to the callback function
    printf("binding this socket to queue '1'\n");
    qh = nfq_create_queue(h,  1, &callback, NULL);
    if (!qh) {
            fprintf(stderr, "error during nfq_create_queue()\n");
            exit(1);
    }
    // Sets the amount of data to be copied to userspace for each packet
    // Last argument, the siez of the packet that we want to get
    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
            fprintf(stderr, "can't set packet_copy mode\n");
            exit(1);
    }

    fd = nfq_fd(h);

    //catch exception
    try {
        ttransport->open();

        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
        }

        ttransport->close();

    } catch (TTransportException e) {
            std::cout << "Error starting client" << std::endl; 

    } catch (IDSControllerException e) {
            std::cout << e.error_description << std::endl;
    
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    #ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
    #endif

    printf("closing library handle\n");
    nfq_close(h);

    return 0;
}
