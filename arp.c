#include "./include/skel.h"
#include "arp.h"
#define IPLEN 4

//functie care adauga o pereche ip->mac in tabela arp
void addEntry(struct ether_arp *r, struct arp_list *arpl){
	struct arp_entry entry;
	memcpy(entry.mac, r->arp_sha, ETH_ALEN);
	memcpy(&(entry.ip), r->arp_spa, IPLEN);
	if(arpl->len < arpl->size){
		arpl->arplist[arpl->len] = entry;
		arpl->len++;
	}
}

//functie care aloca o tabela arp
struct arp_list getArpList(){
	int size = 10;
	struct arp_list arpl;
	arpl.size = size;
	arpl.len = 0;
	arpl.arplist = malloc(size * sizeof(struct arp_entry));
	return arpl;
}