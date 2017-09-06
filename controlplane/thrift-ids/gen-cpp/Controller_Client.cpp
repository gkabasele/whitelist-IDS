#include <iostream>
#include <vector>
#include <cstdio> 
#include <cstdlib>

/* Netfilter queue */
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "srtag.h"
#include "modbus.h"

/* Libcrafter */

#include <crafter.h>



/* Thrift */
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/protocol/TBinaryProtocol.h>

#include "Controller.h"

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

using namespace IDSControllerCpp;


// Initialize client
boost::shared_ptr<TSocket> tsocket(new TSocket("172.0.10.2", 2050));
boost::shared_ptr<TTransport> ttransport(new TBufferedTransport(tsocket));
boost::shared_ptr<TProtocol> tprotocol(new TBinaryProtocol(ttransport)); 

ControllerClient client(tprotocol); 



/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
        int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        struct nfqnl_msg_packet_hw *hwph;
        u_int32_t mark,ifi; 
        int ret;
        struct iphdr *ip_info;
        struct tcphdr *tcp_info;
        struct srtag_hdr *srtag_info;
        //struct mobdus_hdr *modbus_info;
        unsigned char *data;

        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
                id = ntohl(ph->packet_id);
                printf("hw_protocol=0x%04x hook=%u id=%u ",
                        ntohs(ph->hw_protocol), ph->hook, id);
        }

        hwph = nfq_get_packet_hw(tb);
        if (hwph) {
                int i, hlen = ntohs(hwph->hw_addrlen);

                printf("hw_src_addr=");
                for (i = 0; i < hlen-1; i++)
                        printf("%02x:", hwph->hw_addr[i]);
                printf("%02x ", hwph->hw_addr[hlen-1]);
        }

        mark = nfq_get_nfmark(tb);
        if (mark)
                printf("mark=%u ", mark);

        ifi = nfq_get_indev(tb);
        if (ifi)
                printf("indev=%u ", ifi);

        ifi = nfq_get_outdev(tb);
        if (ifi)
                printf("outdev=%u ", ifi);
        ifi = nfq_get_physindev(tb);
        if (ifi)
                printf("physindev=%u ", ifi);

        ifi = nfq_get_physoutdev(tb);
        if (ifi)
                printf("physoutdev=%u ", ifi);

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0){
                printf("payload_len=%d ", ret);
                ip_info  = (struct iphdr *) data;
                printf("IP : src = %u , dest = %u " , ip_info->saddr, ip_info->daddr);
                switch(ip_info->protocol) {
                    case IPPROTO_SRTAG: 
                    {
                        srtag_info = (struct srtag_hdr*) (data + sizeof(*ip_info));
                        printf("SRTag : %u ", srtag_info->dest);

                        tcp_info = (struct tcphdr*) (data + sizeof(*ip_info) +sizeof(*srtag_info));
                        unsigned short dest_port = tcp_info->dest;
                        printf("TCP : dest = %d ", ntohs(dest_port));
                    }    break;
                    case IPPROTO_TCP:
                    {    tcp_info = (struct tcphdr*) (data + sizeof(*ip_info));
                        unsigned short dest_port = ntohs(tcp_info->dest);
                        printf("TCP : dest = %d", dest_port);
                    }   break;
                    default:
                        printf("Unknown protocol");
                        break;
                }
          }
        

        fputc('\n', stdout);

        return id;
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
    /*
    std::string srcip = "10.0.0.0";
    std::string dstip = "10.0.0.0";

    int16_t srcport = 5000;
    int16_t dstport = 502;
    int8_t proto = 6;
    int8_t funcode = 6;
    int16_t length = 100;

    std::vector<int16_t> switches(10);
    

    Flow req ;
    // Set argument of flow 
    req.srcip = srcip; 
    req.dstip = dstip;
    req.srcport = srcport;
    req.dstport = dstport;
    req.proto = proto;
    req.__set_length(length);
    req.__set_funcode(funcode);*/
    

     struct nfq_handle *h;
        struct nfq_q_handle *qh;
        //struct nfnl_handle *nh;
        int fd;
        int rv;
        char buf[4096] __attribute__ ((aligned));

        

            // NFQUEUE packet capture of packet
        printf("opening library handle\n");
        h = nfq_open();
        if (!h) {
                fprintf(stderr, "error during nfq_open()\n");
                exit(1);
        }

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

        printf("binding this socket to queue '1'\n");
        qh = nfq_create_queue(h,  1, &callback, NULL);
        if (!qh) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                exit(1);
        }

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
