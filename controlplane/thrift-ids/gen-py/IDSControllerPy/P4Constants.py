IP_PROTO_TCP = 6
IP_PROTO_SRTAG = '200' 
IP_PROTO_IDSTAG = '201'

# Table name
SEND_FRAME = 'send_frame'
FORWARD = 'forward'
IPV4_LPM = 'ipv4_lpm'
FLOW_ID = 'flow_id'
MODBUS = 'modbus'
MISS_TAG= 'miss_tag_table'
ARP_RESP = 'arp_response'
ARP_FORW_REQ = 'arp_forward_req'
ARP_FORW_RESP = 'arp_forward_resp'
PKT_CLONED = 'pkt_cloned'
TCP_FLAGS = 'tcp_flags'
SRTAG = 'srtag_tab'
IDSTAG = 'idstag_tab'
IDSTAG_ADD_TAB = 'add_tag_ids_tab'
BLOCK_HOSTS = 'block_hosts'
PHYS_VAR_REQ = 'phys_var_req'
PHYS_VAR_RES = 'phys_var_res'

# Action name
DROP = '_drop'
NO_OP = '_no_op'
ADD_TAG = 'add_miss_tag'
REMOVE_TAG = 'remove_miss_tag'
REWRITE = 'rewrite_mac'
DMAC = 'set_dmac'
SET_EGRESS = 'set_egress_port'
ADD_PORT = 'add_expected_port'
RESP = 'respond_arp'
STORE_ARP = 'store_arp_in'
FORWARD_ARP = 'forward_arp'
CLONE_I2E = '_clone_i2e'
REMOVE_IDSTAG = 'remove_ids_tag'
ADD_IDSTAG = 'add_ids_tag'
ADD_MIRROR_TAG = 'add_mirror_tag'


# Value name
CLONE_PKT_FLAG = '1'
MAX_BLOCK_REQUESTS = 3
RULE_ALLOW = 1
RULE_DROP = 0
RULE_ORIGINAL = True
SESSION_ID = "1"

