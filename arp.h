#include "./include/skel.h"

//structura pentru o intrare in tabela de rutare
struct arp_entry {
    __u32 ip;
    uint8_t mac[6];
};

//lista care reprezinta tabela de rutare
struct arp_list{
	int len;
	int size;
	struct arp_entry *arplist;
};

struct arp_list getArpList();
void addEntry(struct ether_arp *r, struct arp_list *arpl);