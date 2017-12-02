@load base/protocols/conn
@load base/protocols/modbus
@load base/frameworks/analyzer
@load base/frameworks/sumstats
@load checkActivityModule

# Set up Bro Server for client to connect to
const broker_port: port = 12345/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "listener";

# Wait this long upon seeing an initial SYN
redef tcp_attempt_delay = 5sec;

global modbus_ports = { 502/tcp, 5020/tcp };

# Function
#global syn_flood_detect: function();

# Event on which the Client can register
global new_conn: event(srcip: addr, sport: port, proto: transport_proto, dstip: addr, dport: port);
global end_conn: event(srcip: addr, sport: port, proto: transport_proto, dstip: addr, dport: port);
global error_modbus: event(srcip: addr, sport: port, dstip: addr, dport: port, funcode: count, code: count);
global flood_victim: event(srcip: addr);


# ex adapted from : https://www.bro.org/sphinx/frameworks/sumstats.html
function syn_flood_detect() 
    {
    print fmt("Initializing Sumstats");
    local r1 = SumStats::Reducer($stream="conn attempted", $apply=set(SumStats::SUM));

    SumStats::create([$name="finding targets",
                      $epoch = 10sec,
                      $reducers = set(r1),
                      $threshold = 10.0,
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                        {
                        return result["conn attempted"]$sum;
                        }, 
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                        {
                        print fmt("%s attempted %.0f or more connections", key$host, result["conn attempted"]$sum);
                        event flood_victim(key$host); 
                        }]); 
    }

event bro_init()
    {
    print fmt("Starting Bro");
    print fmt("Listening on port 12345");

    print fmt("Setting up Modbus Analyzer");
    Analyzer::register_for_ports(Analyzer::ANALYZER_MODBUS, modbus_ports);
    print fmt("Setting up SYN Flood detection - TCP Delay: %s", tcp_attempt_delay);
    syn_flood_detect();
    Broker::enable();
    Broker::auto_event("bro/event/new_conn", new_conn);
    Broker::auto_event("bro/event/end_conn", end_conn);
    Broker::auto_event("bro/event/error_modbus", error_modbus);
    Broker::auto_event("bro/event/flood_victim", flood_victim);
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

#This event is triggered when a SYN + ACK is seen
event connection_established(c:connection)
    {
    print fmt("Monitoring new flow %s <-> %s",c$id$orig_h ,c$id$resp_h);
    schedule CheckActivityModule::check_interval { CheckActivityModule::regular_check(c) };
    }

event connection_first_ACK(c:connection)
    {
    if (c$history == "ShA")
        {
        local proto = get_conn_transport_proto(c$id);
        event new_conn(c$id$orig_h, c$id$orig_p, proto, c$id$resp_h, c$id$resp_p);
        }
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

#Generated for an unsuccessful conection attempt where No SYN/ACK for a certain number of time
event connection_attempt(c: connection)
    {
        print fmt("Unsuccessful connection");
        # Counting the number of unsuccessful connection to an host for each host
        SumStats::observe("conn attempted",
                          SumStats::Key($host=c$id$resp_h),
                          SumStats::Observation($num=1));
    }

#Generated when Bro sees a new active TCP connection for which it didn't see the handshake
event partial_connection(c: connection)
    {
    print fmt("Partial connection");
    }


event bro_done()
    {
    print fmt("Ending Bro");
    }
