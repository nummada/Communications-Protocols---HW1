#include "functions.h"
#define IPLEN 4


//functia de checksum
uint16_t ip_checksum(void* vdata,size_t length) {
	char* data = (char*)vdata;
	uint64_t acc = 0xffff;
	unsigned int offset = ((uintptr_t)data) & 3;
	if (offset) {
		size_t count = 4 - offset;
		if (count > length) {
			count = length;
		}
		uint32_t word = 0;
		memcpy(offset + (char*)&word, data, count);
		acc += ntohl(word);
		data += count;
		length -= count;
	}
	char* data_end = data + (length & ~3);
	while (data != data_end) {
		uint32_t word;
		memcpy(&word, data, 4);
		acc += ntohl(word);
		data += 4;
	}
	length &= 3;
	if (length) {
		uint32_t word = 0;
		memcpy(&word, data, length);
		acc += ntohl(word);
	}
	acc = (acc & 0xffffffff) + (acc >> 32);
	while (acc >> 16) {
		acc = (acc & 0xffff) + (acc >> 16);
	}
	if (offset & 1) {
		acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
	}
	return htons(~acc);
}

//functia care cauta in tabela de rutare, returneaza -1 daca nu face niciun match
int searchRouteTable(int *length, struct in_addr *dst, struct route_table_entry *routelist){
	uint32_t max = 0;
	int idx = -1;
	for(int i = 0 ; i < *length ; i++){
		if(((ntohl(dst->s_addr) & routelist[i].mask) == routelist[i].prefix) && (routelist[i].mask > max)) {
			idx = i;
			max = routelist[i].mask;
		}
	}
	return idx;
}

//functia care realizeaza arp-reply
void arpReply(struct ether_arp *r, packet *m, struct ether_header *eth_hdr){
	unsigned char senderh[ETH_ALEN];
	unsigned char senderip[4];
	memcpy(eth_hdr->ether_dhost, r->arp_sha, ETH_ALEN);

	memcpy(senderh, r->arp_tha, ETH_ALEN);
	memcpy(r->arp_tha, r->arp_sha, ETH_ALEN);
	memcpy(r->arp_sha, senderh, ETH_ALEN);

	memcpy(senderip, r->arp_tpa, IPLEN);
	memcpy(r->arp_tpa, r->arp_spa, IPLEN);
	memcpy(r->arp_spa, senderip, IPLEN);

	r->arp_op = htons(ARPOP_REPLY);

	get_interface_mac(m->interface, r->arp_sha);
	
	memcpy(eth_hdr->ether_dhost, r->arp_tha, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, r->arp_sha, ETH_ALEN);
	send_packet(m->interface, m);
}