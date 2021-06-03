--trivial protocol example
-- declare our protocol
srtag_proto = Proto("srtag","SRTAG Protocol")

orig_addr = ProtoField.uint32("srtag.orig_addr", "orig_addr", base.DEC)
switch_id = ProtoField.uint16("srtag.switch_id", "switchID", base.DEC)
proto = ProtoField.uint8("srtag.proto", "proto", base.DEC)
padding = ProtoField.uint8("srtag.padding", "padding", base.DEC)

srtag_proto.fields = {orig_addr, switch_id, proto, padding}

-- create a function to dissect it
function srtag_proto.dissector(buffer,pinfo,tree)
    length = buffer:len()
    if length == 0 then return end
    
    pinfo.cols.protocol = "SRTAG"
    local subtree = tree:add(srtag_protocol, buffer(),"SRTAG Protocol Data")

    subtree:add(orig_addr, buffer(0,4))
    subtree:add(switch_id, buffer(4,2))
    subtree:add(proto, buffer(6,1))
    subtree:add(padding, buffer(7,1))
    
end

-- load the udp.port table
ip_table = DissectorTable.get("ip.proto")
-- register our protocol to handle ip proto 200
ip_table:add(200,srtag_proto)
