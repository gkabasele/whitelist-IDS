#include <iostream>
#include <string>
#include <vector>
#include <cstdio> 
#include <cstdlib>
#include <cstdint>
#include <thread>
#include <iterator>
#include <algorithm>
#include <set>
#include <random>
#include <cmath>
#include <mutex>
#include <cerrno>
#include <memory>
#include <chrono>
#include <fstream>
#include <unistd.h>

/* Netfilter queue */
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <poll.h>
#include <sys/socket.h>

/* Libcrafter */
#include <crafter.h>
#include <crafter/Utils/TCPConnection.h>

/* Broker Library*/
#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

/* Thrift */
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/protocol/TBinaryProtocol.h>

/* Utils */

#include "Controller.h"
#include "Controller_Client.h"
#include "srtag.h"
#include "modbus.h"
#include "flows.h"

/* Logging */
#include <spdlog/spdlog.h>


/* Index of value in message vector from broker agent*/
#define TOPIC 0
#define SRCIP 1
#define SPORT 2
#define PROTO 3
#define DSTIP 4
#define DPORT 5
#define FUNCODE 5
#define EXP_CODE 6
#define TCP_LABEL "tcp"
#define UDP_LABEL "udp"
#define IPERF_PORT 5021
/* Header size in bytes*/
#define MBAP_LEN 6
#define MAX_TCP_LEN 60
#define MAX_IP_LEN 60
#define MAX_MODBUS_LEN 255

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

using namespace IDSControllerCpp;


// Initialize two clients (Broker and IDS)
boost::shared_ptr<TSocket> tsocket(new TSocket("172.0.10.2", 2050));
boost::shared_ptr<TTransport> ttransport(new TBufferedTransport(tsocket));
boost::shared_ptr<TProtocol> tprotocol(new TBinaryProtocol(ttransport)); 

boost::shared_ptr<TTransport> m_tsocket(new TSocket("172.0.10.2", 2050));
boost::shared_ptr<TTransport> m_ttransport(new TBufferedTransport(tsocket));
boost::shared_ptr<TProtocol> m_tprotocol(new TBinaryProtocol(ttransport)); 


ControllerClient client(tprotocol); 
ControllerClient m_client(m_tprotocol);

// Logging init
// setting async mode
auto ids_logger = spdlog::basic_logger_mt("basic_logger", "logs/ids.txt");


// List of possible targets of SYN FLOOD
std::set<std::string> flood_targets;
std::mutex flood_targets_mutex;

// protocol requiring real-time communication
std::set<__u16> real_com;
int number_recv_pkt = 0;

// Use map ?  net->mask
std::vector<std::string> networks;
std::vector<std::string> masks;
// IP addresses of MTU
std::set<std::string> mtus;

bool is_mtu(std::string ip)
{
    auto res = mtus.find(ip); 
    return (res != mtus.end());
}
/* Convert string to a u32 int*/
__u32 to_ipv4_uint(std::string ip)
{
    int a, b, c, d;
    __u32 addr = 0;
    
    // Check format of the string
    if ( sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
        return 0;

    addr = a << 24;
    addr |= b << 16;
    addr |= c << 8;
    addr |= d;
    return addr;
}

/* Check if address in range*/
bool is_in_range( __u32 ip_addr, std::string network, std::string mask)
{
    __u32 network_addr = to_ipv4_uint(network); 
    __u32 mask_addr = to_ipv4_uint(mask);


    // Get first and last address of the range
    __u32 net_lower = (network_addr & mask_addr);
    __u32 net_upper = (net_lower | (~mask_addr));
    
    return (ip_addr >= net_lower && ip_addr <= net_upper);
}

// FIXME use iterator
bool allowed_addr(__u32 ip_addr)
{
    bool allow = false;
    // Check if srcip in range
    for( unsigned int i = 0; i < networks.size() ; i++){
        if(is_in_range(ip_addr, networks[i], masks[i]))
        {
            allow = true;
            break;
        }
    }
    return allow;
}
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
    req = form_request(srcip, dstip, srcport, dstport, proto);

    /* Get TCP header options */
    if (is_modbus_pkt(tcp_info)) { 
        index += (tcp_info->doff*4);
        modbus_info = (struct modbus_hdr*) (data + index);                
        /* TODO check if int is too big for short values*/
        int8_t funcode = (int8_t) modbus_info->funcode;
        int16_t modbus_length = (int16_t) ntohs(modbus_info->len);
        printf("Modbus Pkt: funcode: %d, length: %d\n", funcode, modbus_length);
        req.__set_length(modbus_length);
        req.__set_funcode(funcode); 
    }
    switches.push_back((int16_t) srtag_info->identifier);
    client.allow(req, switches); 
    
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



__u64 generate_nonce()
{
    std::random_device rd;
    std::mt19937_64 e2(rd());
    std::uniform_int_distribution<long long int> dist(std::llround(std::pow(2,61)), std::llround(std::pow(2,62)));
    return dist(e2);
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    int ret;
    struct iphdr *ip_info;
    struct tcphdr *tcp_info;
    struct srtag_hdr *srtag_info;
    std::vector<int16_t> switches;
    Flow req;
    
    number_recv_pkt +=1; 
    ids_logger->info("Number of received packet: %d", number_recv_pkt);
    
    unsigned char *data;

    // return header of the netlink packet    
    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
            id = ntohl(ph->packet_id);
            ids_logger->info("hw_protocol=0x%04x hook=%u id=%u ",
              ntohs(ph->hw_protocol), ph->hook, id);
    }
       
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
            ids_logger->info( "payload_len=%d ", ret);
            ip_info  = (struct iphdr *) data;
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
                            ids_logger->info("Received UDP packet");
                            break;
                        }                         
                        default:
                        {
                            ids_logger->info("Received packet from an unknown protocol");
                            break;
                        }
                    }
                }
                case IPPROTO_TCP:
                {    
                    struct sockaddr_in connection;
                    int sockfd;
                    int optval = 1;
                    bool send_pkt = true;

                    tcp_info = (struct tcphdr*) (data + (ip_info->ihl*4));
                    __u16 dest_port = ntohs(tcp_info->dest);
                    __u16 src_port = ntohs(tcp_info->source);
                    std::string dstip = to_ipv4_string(ip_info->daddr);

                    if (! allowed_addr(ntohl(ip_info->saddr)) || ! allowed_addr(ntohl(ip_info->daddr))){
                        std::cout << "Dropping packet: Invalid Ip" << std::endl;
                        return id; 
                    }
                     

                    ids_logger->info("srcip: %u , destip: %u, sport: %u, dport: %u  " , ip_info->saddr, ip_info->daddr, src_port,dest_port);
                    // Check if dstip is a target victim
                    flood_targets_mutex.lock();
                    auto res = flood_targets.find(dstip);
                    bool is_target = (res != flood_targets.end());
                    send_pkt = !( tcp_info->syn == 1 &&  is_target);
                    flood_targets_mutex.unlock();
                    if (! send_pkt){
                       std::cout << "Dropping packet: Syn Flood" << std::endl;
                       return id; 
                    }

                    int8_t proto = (int8_t) IPPROTO_TCP;
                    int16_t srcport = (int16_t) src_port;
                    int16_t dstport = (int16_t) dest_port;
                    req = form_request(srcip, dstip, srcport, dstport, proto);
                    if (is_modbus_pkt(tcp_info)) { 
                        
                        unsigned int index = (ip_info->ihl*4) + (tcp_info->doff*4);
                        // Check packet format, too large 
                        if (ret > (MAX_IP_LEN + MAX_TCP_LEN + MAX_MODBUS_LEN))
                            return id;
                        struct modbus_hdr* modbus_info = (struct modbus_hdr*) (data + index);                
                        int8_t funcode = (int8_t) modbus_info->funcode;
                        int16_t modbus_length = (int16_t) ntohs(modbus_info->len);
                        ids_logger->info("Modbus Pkt: funcode: %d, length: %d", modbus_info->funcode, ntohs(modbus_info->len));
                        // Check if packet malformed
                        if ((unsigned int)ret != (index + MBAP_LEN + ntohs(modbus_info->len))) 
                            return id;

                        if (modbus_info->funcode < 128) {
                            // Is it a Diagnostic function
                            if (modbus_info->funcode == 8) {
                                struct modbus_diag_hdr* diag_info = (struct modbus_diag_hdr*) (data + index + sizeof(struct modbus_hdr));
                                __u16 diag_func = diag_info->subfuncode;
                                if (!(is_mtu(srcip) || is_mtu(dstip)))
                                    send_pkt = !(diag_func == 1 || diag_func == 4 || diag_func == 10);
                            }
                            if (send_pkt) {
                                switches.push_back((int16_t) 0);
                                req.__set_length(modbus_length);
                                req.__set_funcode(funcode); 
                                m_client.allow(req, switches); 
                            }
                        }
                    }

                    if (send_pkt){
                        Flow n_req = form_request(srcip, dstip, srcport, dstport, proto);
                        std::vector<int16_t> nonce_blocks;
                        __u64 nonce = generate_nonce();  
                        for (int i = 0; i < 4; i++) {
                           __u16 block = (__u16) (nonce >> i*16); 
                           nonce_blocks.push_back((int16_t)block);  
                        }
                        m_client.redirect(n_req, nonce_blocks);
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
                        if (sendto(sockfd, data, ret, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr)) < 0){
                            perror("sendto");
                            exit(EXIT_FAILURE);
                        } 
                        close(sockfd);
                        //free(crafted_packet);
                    }

                }   break;
                default:
                {
                    break;
                }
            }
      }
    
    
    //fputc('\n', stdout);
    
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
    u_int32_t id = print_pkt(nfa);
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

void broker_comm()
{
    broker::init();
    broker::endpoint bro_client("client");
    bro_client.peer("127.0.0.1",12345);
    //FIXME Parameterization and create handler for each queue
    broker::message_queue new_conn_queue("bro/event/new_conn", bro_client);
    broker::message_queue end_conn_queue("bro/event/end_conn", bro_client);
    broker::message_queue error_modbus_queue("bro/event/error_modbus", bro_client);
    broker::message_queue flood_victim_queue("bro/event/flood_victim", bro_client);

    pollfd ufds[4];
    ufds[0].fd = new_conn_queue.fd();
    ufds[0].events = POLLIN;
    ufds[1].fd = end_conn_queue.fd();
    ufds[1].events = POLLIN;
    ufds[2].fd = error_modbus_queue.fd();
    ufds[2].events = POLLIN;
    ufds[3].fd = flood_victim_queue.fd();
    ufds[3].events = POLLIN;
    Flow req;
    std::vector<int16_t> switches;
    //catch exception
    try {
        ttransport->open();
        while(1){
            int r = poll(ufds, 4, -1);
            if (r == -1){
                std::cerr << "Error in poll" << std::endl;
            } else {
                if (ufds[0].revents & POLLIN) {
                    for(auto& msg : new_conn_queue.want_pop()){
                        std::cout << broker::to_string(msg) << std::endl;
                        std::string srcip = broker::to_string(msg[SRCIP]);
                        std::string dstip = broker::to_string(msg[DSTIP]);
                        unsigned long srcport = std::stoul(broker::to_string(msg[SPORT]));
                        unsigned long dstport = std::stoul(broker::to_string(msg[DPORT]));
                        unsigned long proto = 0;
                        if( broker::to_string(msg[PROTO]).compare(TCP_LABEL) == 0) {
                            proto = 6;
                        } else if (broker::to_string(msg[PROTO]).compare(UDP_LABEL) == 0){
                            proto = 17;
                        } else {
                            exit(-1);
                        }
                        if (! allowed_addr(to_ipv4_uint(srcip)) || ! allowed_addr(to_ipv4_uint(dstip)))
                            break;
                        req = form_request(srcip,dstip, (int16_t) srcport, (int16_t) dstport, (int8_t) proto);
                        //FIXME retrieve switch from srcip
                        switches.push_back((int16_t) 0);
                        // Checking it is a delay sensitive communication
                        auto search  = real_com.find(dstport);
                        if (search != real_com.end()){
                            client.allow(req, switches);
                        }
                    }

                }
                if (ufds[1].revents & POLLIN) {
                    for(auto& msg : end_conn_queue.want_pop()){
                        std::cout << broker::to_string(msg) << std::endl;
                        
                    }
                }

                if (ufds[2].revents & POLLIN) {
                    for(auto& msg : error_modbus_queue.want_pop()){
                        std::cout << broker::to_string(msg) << std::endl;
                        // topic, srcip, sport, dstip, dport, funcode, code
                        std::string srcip = broker::to_string(msg[1]);
                        unsigned long srcport = std::stoul(broker::to_string(msg[2]));
                        std::string dstip = broker::to_string(msg[3]);
                        unsigned long dstport = std::stoul(broker::to_string(msg[4]));
                        unsigned long funcode = std::stoul(broker::to_string(msg[5]));
                        unsigned long exception_code = std::stoul(broker::to_string(msg[6]));
                        req = form_request(srcip,dstip,(int16_t) srcport, (int16_t) dstport, (int8_t) IPPROTO_TCP);
                        // block if either, 1 = Illegal Function code, 2 = Illegal Data Address, 3 = Illegal Data Value
                        if(funcode > 127 && exception_code <= 3 && srcport == 5020)
                        {
                            // Length of a data pdu when exception code  
                            req.__set_length(3);
                            req.__set_funcode(funcode); 
                            switches.push_back((int16_t) 0);
                            client.block(req, switches);
                        }
                         
                    }

                    
                }

                if (ufds[3].revents & POLLIN) {
                    for(auto& msg : flood_victim_queue.want_pop()){
                        std::cout << broker::to_string(msg) << std::endl;
                        std::string srcip = broker::to_string(msg[1]);
                        std::cout <<"Adding host " << srcip << " to list of possible flooding target" << std::endl; 
                        flood_targets_mutex.lock();
                        flood_targets.insert(srcip);  
                        flood_targets_mutex.unlock();
                    }
                }
                        
            }

        }

        ttransport->close();

    } catch (TTransportException e) {
            std::cout << "Error starting client" << std::endl; 

    } catch (IDSControllerException e) {
            std::cout << e.error_description << std::endl;
    
    }
    exit(0);
}

void parse_config_file(std::string name, std::string value)
{
    if(name == "MTUS" || name == "REALCOM" || name == "NETWORKS") {
        std::string res;
        for(std::string::iterator it=value.begin(); it != value.end(); ++it)
        {
            if(*it =='[')
                continue; 
            else if(*it == ',' || *it == ']'){
                if (name == "MTUS"){
                    mtus.insert(res);         
                    res.clear();
                }
                else if(name == "REALCOM") {
                    real_com.insert((__u16)stoi(res));
                    res.clear();
                }
                else if(name == "NETWORKS") {
                    auto delimiterPos = res.find('/');
                    auto network = res.substr(0, delimiterPos); 
                    auto slash = (__u32)stoi(res.substr(delimiterPos + 1));
                    __u32 mask = 0xFFFF << slash; 
                    networks.push_back(network);
                    masks.push_back(to_ipv4_string(htonl(mask)));
                    res.clear();
                }
            }
            else
                res += *it;
        }

    }

}

void read_config_file(std::string filename)
{
    std::ifstream cFile(filename);
    if(cFile.is_open())
    {
        ids_logger->info("Opening Configuration file");
        std::string line;
        while(std::getline(cFile, line)){
            // Remove space from line
            line.erase(std::remove_if(line.begin(), line.end(), isspace), line.end());
            if(line[0] == '#' || line.empty())
                continue;
            auto delimiterPos = line.find(":");
            auto name = line.substr(0, delimiterPos);
            auto value = line.substr(delimiterPos + 1);
            parse_config_file(name, value);
        } 
        cFile.close();
    } else {
        std::cerr << "Unable to open config file " << filename << std::endl;
        exit(1);
    }
}

int main(int argc, char **argv)
{
        

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    // TODO: what happens if packet too big
    char buf[4096] __attribute__ ((aligned));
    uint32_t queuelen = 2048;
    std::string config_filename;

    int opt;
    while((opt = getopt(argc, argv, "c:")) != -1) {
        switch (opt)
        {
            case 'c': 
                config_filename = optarg; 
                break;
            default: 
                std::cerr << "Usage: " << argv[0] << " -c <config file>" << std::endl;
                exit(1);
        }
    }

    read_config_file(config_filename); 

    std::cout << "MTU: " << std::endl;
    for (auto it = mtus.begin(); it != mtus.end();++it){
        std::cout << *it << std::endl;     
    }
    std::cout << "Networks: " << std::endl;
    for (auto it = networks.begin(); it != networks.end(); ++it){
        std::cout << *it << std::endl;
    }
    std::cout << "Mask: " << std::endl;
    for (auto it = masks.begin(); it != masks.end(); ++it) {
        std::cout << *it << std::endl;
    }
    std::cout << "Real comm: " << std::endl;
    for (auto it = real_com.begin(); it != real_com.end(); ++it) {
        std::cout << *it << std::endl;
    } 

    spdlog::set_async_mode(8192, spdlog::async_overflow_policy::block_retry,
                           nullptr,
                           std::chrono::seconds(2)); 
                
    // NFQUEUE packet capture of packet
    ids_logger->info("Opening library handle");
    h = nfq_open();
    if (!h) {
            std::cerr << "error during nfq_open" << std::endl;
            exit(1);
    }

    
    //obsolete since kernel 3.8
    ids_logger->info("unbinding existing nf_queue handler for AF_INET (if any)");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
            std::cerr << "error during nfq_unbind_pf" << std::endl;
            exit(1);
    }

    ids_logger->info("binding nfnetlink_queue as nf_queue handler for AF_INET");
    if (nfq_bind_pf(h, AF_INET) < 0) {
            std::cerr << "error during nfq_bind_pf" << std::endl;
            exit(1);
    }

    // Last argument, some data to pass to the callback function
    ids_logger->info("binding this socket to queue '1'");
    qh = nfq_create_queue(h,  1, &callback, NULL);
    if (!qh) {
            std::cerr << "error during nfq_create_queue" << std::endl;
            exit(1);
    }

    // Increase size of kernel queue
    ids_logger->info("Increasing queue size");
    if (nfq_set_queue_maxlen(qh, queuelen) < 0) {
            std::cerr << "can't set queue size" << std::endl;
            exit(1);
    }
    
    // Sets the amount of data to be copied to userspace for each packet
    // Last argument, the siez of the packet that we want to get
    ids_logger->info("setting copy_packet mode");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
            std::cerr << "can't set packet_copy mode" << std::endl;
            exit(1);
    }

    fd = nfq_fd(h);

    int enobuf_value = 1;
    setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &enobuf_value, sizeof(enobuf_value));
    std::thread broker_th(&broker_comm); 
    try {
        m_ttransport->open();
        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
                nfq_handle_packet(h, buf, rv);
        }
        if (rv <0) {
            std::cerr << "Error when reading" << std::endl;
            exit(1);
    }
        m_ttransport->close();
    } catch (TTransportException e) {
        std::cout << "Error starting client" << std::endl;

    } catch (IDSControllerException e) {
        std::cout << e.error_description << std::endl;
    }
    broker_th.join();

    ids_logger->info("unbinding from queue 0");
    nfq_destroy_queue(qh);

    #ifdef INSANE
    // normally, applications SHOULD NOT issue this command, since
    // it detaches other programs/sockets from AF_INET, too ! 
    std::cout << "unbinding from AF_INET" << std::endl;
    nfq_unbind_pf(h, AF_INET);
    #endif

    ids_logger->info("Closing library handle");
    nfq_close(h);
    ids_logger->flush();
    spdlog::drop_all();

    return 0;
}
