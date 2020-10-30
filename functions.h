#ifndef FUNC
#define FUNC

#include "./include/skel.h"
#include "myparser.h"

uint16_t ip_checksum(void* vdata,size_t length);
int searchRouteTable(int *length, struct in_addr *dst, struct route_table_entry *routelist);
void arpReply(struct ether_arp *r, packet *m, struct ether_header *eth_hdr);
#endif