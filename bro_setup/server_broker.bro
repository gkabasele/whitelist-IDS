@load base/protocols/conn
@load base/protocols/modbus
@load base/frameworks/analyzer

# Set up Bro Server for client to connect to
const broker_port: port = 12345/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "listener";

global modbus_ports = { 502/tcp, 5020/tcp };

# Event on which the Client can register
global new_conn: event(srcip: addr, sport: port, proto: transport_proto, dstip: addr, dport: port);
global end_conn: event(srcip: addr, sport: port, proto: transport_proto, dstip: addr, dport: port);
global error_modbus: event(srcip: addr, sport: port, dstip: addr, dport: port, funcode: count, code: count);


event bro_init()
    {
    print fmt("Starting Bro");
    print fmt("Listening on port 12345");

    print fmt("Setting up Modbus Analyzer");
    Analyzer::register_for_ports(Analyzer::ANALYZER_MODBUS, modbus_ports);
    Broker::enable();
    Broker::auto_event("bro/event/new_conn", new_conn);
    Broker::auto_event("bro/event/end_conn", end_conn);
    Broker::auto_event("bro/event/error_modbus", error_modbus);
    Broker::listen(broker_port, "127.0.0.1");
    }


event Broker::incoming_connection_established(peer_name: string)
    {
    print "Broker::incoming_connection_established", peer_name; 
    }

event Broker::incoming_connection_broken(peer_name: string)
    {
    print "Broker::incoming_connection_broker", peer_name;
    terminate();
    }

event connection_established(c:connection)
    {
    local proto = get_conn_transport_proto(c$id);
    event new_conn(c$id$orig_h, c$id$orig_p, proto, c$id$resp_h, c$id$resp_p);
    }

event connection_finished(c:connection)
    {
    local proto = get_conn_transport_proto(c$id);
    event end_conn(c$id$orig_h, c$id$orig_p, proto, c$id$resp_h, c$id$resp_p);
    }

event modbus_exception(c: connection, headers: ModbusHeaders, code: count)
    {
    event error_modbus(c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, headers$function_code,code); 
    }

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
    {
    # exception from the server  
    if( ( headers$function_code > 127) && (!is_orig) )
        {
        event error_modbus(c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p, headers$function_code,1);
        }
    }

event bro_done()
    {
    print fmt("Ending Bro");
    }

