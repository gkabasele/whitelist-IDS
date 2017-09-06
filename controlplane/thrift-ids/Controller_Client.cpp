#include <iostream>

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

    int16_t identifier = 1;

    _Flow f ;
    // Set argument of flow 
    _FlowRequest req ;
    // Set argument of flow request

    boost::shared_ptr<TSocket> socket(new TSocket("localhost", 9090));
    boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
    boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport)); 

    ControllerClient client(protocol); 
    //catch exception

    transport->open();
    
    std::cout << "Sending Request" << std::endl;
    client.mirror(req);
    std::cout << "Received Response" << std::endl; 

    transport->close();



    return 0;

}
