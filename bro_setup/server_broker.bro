@load base/protocols/conn

const broker_port: port = 12345/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "listener";

global new_conn: event(srcip: addr, sport: port, proto: transport_proto, dstip: addr, dport: port);
global end_conn: event(srcip: addr, sport: port, proto: transport_proto, dstip: addr, dport: port);

event bro_init()
    {
    print fmt("Starting Bro");
    Broker::enable();
    Broker::auto_event("bro/event/new_conn", new_conn);
    Broker::auto_event("bro/event/end_conn", end_conn);
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

event bro_done()
    {
    print fmt("Ending Bro");
    }
