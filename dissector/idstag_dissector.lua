--declare our protocol
idstag_proto = Proto("idstag", "IDS tag")
-- create a function to dissect it
function idstag_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "IDSTag"
    local subtree = tree:add(idstag_proto, buffer(), "IDStag Data")
    subtree:add(buffer(0,8),"Nounce : " .. buffer(0,8):uint64())
    local proto = buffer(8,1):uint()
    subtree:add(buffer(8,1), "Original Protocol: " .. buffer(8,1):uint())
    if proto == 6 then
        -- 8 is the headerlen
        Dissector.get("tcp"):call(buffer(8):tvb(), pinfo, tree)
    end
end

-- load the ip port table
ip_table = DissectorTable.get("ip.proto")
-- register protocol to handle ip protocol 6
ip_table:add(201, idstag_proto)
