#include <iostream>
#include <vector>

#include "Controller.h"

#include <thrift/transport/TSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/protocol/TBinaryProtocol.h>

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

using namespace IDSControllerCpp;

int main(int argc, char **argv)
{
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
    req.__set_funcode(funcode);
    
    boost::shared_ptr<TSocket> socket(new TSocket("localhost", 9090));
    boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
    boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport)); 

    ControllerClient client(protocol); 


    //catch exception
    try {
        transport->open();
        
        std::cout << "Sending Request" << std::endl;
        client.mirror(req, switches);
        std::cout << "Received Response" << std::endl; 

        transport->close();
    } catch (TTransportException e) {
        std::cout << "Error starting client" << std::endl; 

    } catch (IDSControllerException e) {
        std::cout << e.error_description << std::endl;
    
    }


    return 0;

}
