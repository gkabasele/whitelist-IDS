#ifndef CONTROLLER_CLIENT_H
#define CONTROLLER_CLIENT_H

#include<iostream>
#include<cstdio>
#include<cstdlib>
#include<cstdint>
#include<cstring>
#include<linux/tcp.h>

#include "Controller.h"
#include "modbus.h"
#include "srtag.h"
#include "flows.h"

__u32 to_ipv4_uint(std::string ip);

bool allowed_addr(__u32 ip_addr);
bool is_in_range(__u32 ip_addr, std::string network, std::string mask);

std::string to_ipv4_string(__u32 ip);

IDSControllerCpp::Flow form_request(std::string srcip, std::string dstip, int16_t srcport, int16_t dstport,
                                    int8_t proto);

bool is_modbus_pkt(struct tcphdr* tcp_info);

void handle_tcp_pkt(struct iphdr* ip_info, struct srtag_hdr *srtag_info, 
                    std::vector<int16_t> switches, unsigned char* data, int ret);

                    
static u_int32_t print_pkt (struct nfq_data *tb);

unsigned char* forge_packet(unsigned int length, struct iphdr* ip_info,struct srtag_hdr* srtag_info,
                            struct tcphdr* tcp_info, struct modbus_hdr* modbus_info);

void treat_pkt(char* data, int* verdict);
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data);

unsigned short in_cksum(unsigned short *addr, int len);

void broker_comm();

__u64 generate_nounce();

#endif
