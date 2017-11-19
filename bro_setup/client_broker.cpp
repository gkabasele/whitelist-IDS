#include <iostream>
#include <string>
#include <poll.h>
#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#define TOPIC 0
#define SRCIP 1
#define SPORT 2
#define PROTO 3
#define DSTIP 4
#define DPORT 5
#define TCP "tcp"
#define UDP "udp"

/*
    srcip : std::string
    dstip : std::string
    sport : uint16_t
    dport : uint16_t
    proto : uint8_t
*/


int main()
{
    
    broker::init();
    broker::endpoint client("client");
    client.peer("127.0.0.1",12345);
    broker::message_queue new_conn_queue("bro/event/new_conn", client);
    broker::message_queue end_conn_queue("bro/event/end_conn", client);
    pollfd ufds[2];
    /*
    pollfd pfd{new_conn_queue.fd(), POLLIN, 0};
    pollfd pfd{end_conn_queue.fd(), POLLIN, 0};
    ufds[0] = pfd{new_conn_queue.fd(), POLLIN, 0};
    ufds[1] = pfd{end_conn_queue.fd(), POLLIN, 0};*/
    ufds[0].fd = new_conn_queue.fd();
    ufds[0].events = POLLIN;
    ufds[1].fd = end_conn_queue.fd();
    ufds[1].events = POLLIN;
    while(1){
        //poll(&pfd, 1, -1);
        int r = poll(ufds, 2, -1);
        if (r == -1) {
            perror("poll"); //error occurred in poll()
        } else {
            //check for event in new_conn 
            if(ufds[0].revents & POLLIN) {
                for (auto& msg : new_conn_queue.want_pop() ){
                    std::cout << broker::to_string(msg) << std::endl;
                    std::string title = broker::to_string(msg[TOPIC]);
                    std::string srcip = broker::to_string(msg[SRCIP]);
                    std::string dstip = broker::to_string(msg[SRCIP]);
                    unsigned long sport = std::stoul(broker::to_string(msg[SPORT]));
                    unsigned long dport = std::stoul(broker::to_string(msg[DPORT]));
                    unsigned long proto = 0; 
                    if(broker::to_string(msg[PROTO]).compare(TCP) == 0) {
                        proto = 6;
                    } else if(broker::to_string(msg[PROTO]).compare(UDP) == 0) {
                        proto = 17;
                    } else {
                        return -1;
                    }
                    std::cout << "(E " << srcip << "," << sport << "," << proto << "," << dstip << "," << dport << " )" << std::endl;
                }
                //get_message(new_conn_queue);
            }  
            if(ufds[1].revents & POLLIN) {
                for (auto& msg : end_conn_queue.want_pop() ){
                    std::cout << broker::to_string(msg) << std::endl;
                    std::string title = broker::to_string(msg[TOPIC]);
                    std::string srcip = broker::to_string(msg[SRCIP]);
                    std::string dstip = broker::to_string(msg[SRCIP]);
                    unsigned long sport = std::stoul(broker::to_string(msg[SPORT]));
                    unsigned long dport = std::stoul(broker::to_string(msg[DPORT]));
                    unsigned long proto = 0; 
                    if(broker::to_string(msg[PROTO]).compare(TCP) == 0) {
                        proto = 6;
                    } else if(broker::to_string(msg[PROTO]).compare(UDP) == 0) {
                        proto = 17;
                    } else {
                        return -1;
                    }
                    std::cout << "(F " << srcip << "," << sport << "," << proto << "," << dstip << "," << dport << " )" << std::endl;
                }
            }  
                //get_message(end_conn_queue);
        }
    }
    

    return 0;
}
