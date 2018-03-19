-- declare our protocol
srtag_proto = Proto("srtag","Scada Redirection Tag")
-- create a function to dissect it
function srtag_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "SRTag"
    local subtree = tree:add(srtag_proto, buffer(), "Srtag Data")
    subtree:add(buffer(0,4), "Original Destination IP: " .. tostring(buffer(0,4):ipv4()))
    subtree:add(buffer(4,2), "Switch identifier: " .. buffer(4,2):uint())
    local proto = buffer(6,1):uint()
    subtree:add(buffer(6,1), "Original Protocol: " .. buffer(6,1):uint())
    local reason = buffer(7,1):uint()
    local reason_text = "Unknown"
    if (reason == 0) then
        reason_text = "MISS" 
    elseif (reason == 1) then
        reason_text = "CLONE"
    end
    subtree:add(buffer(7,1), "Reason: " .. reason_text) 
    if proto == 6 then
        -- 8 is the headerlen
        Dissector.get("tcp"):call(buffer(8):tvb(), pinfo, tree)
    end
end

-- load the ip port table
ip_table = DissectorTable.get("ip.proto")
-- register protocol to handle ip protocol 6
ip_table:add(200, srtag_proto)
