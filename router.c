#include "./include/skel.h"
#include "myparser.h"
#include "functions.h"
#include "./include/queue.h"
#include "arp.h"

#define IPLEN 4

//functie care realizeaza checksum incremental rfc 1624
void checksum_incremental(struct ip *ip) {
    unsigned short before = ~(((ip->ip_ttl) << 8) + ip->ip_p);
    ip->ip_ttl--;
    unsigned short after = ((ip->ip_ttl << 8) + ip->ip_p);
    unsigned short old = ~ntohs(ip->ip_sum);
    uint32_t new = (uint32_t)old + before + after;
    ip->ip_sum = htons(~((uint16_t)(new >> 16) + (new & 0xffff)));
}

//functie care trimite un pachet doar daca checksum este bun
void send_if_good_check(struct ip *ip, packet *p){
    u_short old_check = ip->ip_sum;
    ip->ip_sum = 0;
    ip->ip_sum = ip_checksum((void*)ip, sizeof(struct ip));
    if (old_check == ip->ip_sum) {
        checksum_incremental(ip);
        send_packet(p->interface, p);
    }
}

//functie care trimite un pachet in caz de "destination unreachable"
void destinationUnreachable(packet *m) {
	struct ether_header* eth_hdr = (struct ether_header *)(m->payload);
	struct ip *ip = (struct ip *)(m->payload + sizeof(struct ether_header));
	struct in_addr src = ip->ip_src;
	struct in_addr dst = ip->ip_dst;
	packet r;
	r.len = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr);
	r.interface = m->interface;

	struct ether_header *sender_eth = (struct ether_header *)(r.payload);
	struct iphdr *sender_ip = (struct iphdr *)(r.payload + sizeof(struct ether_header));
	struct icmphdr *sender_icmp = (struct icmphdr *)(r.payload + sizeof(struct ether_header)
		+ sizeof(struct iphdr));
	get_interface_mac(r.interface, sender_eth->ether_shost);
	memcpy(sender_eth->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
	sender_eth->ether_type = eth_hdr->ether_type;
	//completez header-ul ip
	sender_ip->version = 4;
	sender_ip->ihl = 5;
	sender_ip->tos = 0;
	sender_ip->id = 0;
	sender_ip->frag_off = 0;
	sender_ip->tot_len = htons(2 * sizeof(struct iphdr)  + sizeof(struct icmphdr));
	sender_ip->ttl = 255;
	sender_ip->protocol = IPPROTO_ICMP;
	sender_ip->daddr = src.s_addr;
	sender_ip->saddr = dst.s_addr;
	sender_ip->check = 0;
	sender_ip->check = (ip_checksum((void*)(sender_ip), sizeof(struct iphdr)));

	//completez header-ul icmp
	memset(sender_icmp, 0, sizeof(struct icmphdr));
	memcpy(sender_icmp + sizeof(struct icmphdr), ip, sizeof(struct ip));
	sender_icmp->type = 3;
	sender_icmp->code = 0;
	sender_icmp->checksum = 0;
	sender_icmp->checksum = ip_checksum((void*)(sender_icmp), sizeof(struct icmphdr) + sizeof(struct iphdr));
	send_packet(r.interface, &r);
}

//functie care trimite un arp request
void arpRequest(packet *m, int *length, struct route_table_entry *routelist,
	struct ether_header *eth_hdr, struct in_addr *dst){

	packet p;
	u_char broadcast [ETH_ALEN];
	struct ether_header *eth_hdr2 = (struct ether_header *)(p.payload);
	struct ether_arp *r2 = (struct ether_arp*)(p.payload + sizeof(struct ether_header));
	int idxOfTarget = searchRouteTable(length, dst, routelist);

	//nu am gasit match in tabela de rutare
	if (idxOfTarget == -1){
		destinationUnreachable(m);
	}else{
		for(int i = 0 ; i < ETH_ALEN ; i++){
			broadcast[i] = 0xff;
		}

		eth_hdr2->ether_type = htons(ETHERTYPE_ARP);
		memcpy(eth_hdr2->ether_dhost, broadcast, ETH_ALEN);

		r2->arp_hrd = htons(ARPHRD_ETHER), r2->arp_pro = 8, r2->arp_hln = 6, r2->arp_pln = 4;
		r2->arp_op = htons(ARPOP_REQUEST);


		get_interface_mac(routelist[idxOfTarget].interface, r2->arp_sha);
		memcpy(eth_hdr2->ether_shost, r2->arp_sha, ETH_ALEN);

		char* ip = get_interface_ip(routelist[idxOfTarget].interface);

		for(int i = 0 ; i < ETH_ALEN ; i++){
			broadcast[i] = 0x00;
		}
		memcpy(r2->arp_spa, ip, IPLEN);
		memcpy(r2->arp_tha, broadcast, ETH_ALEN);
		memcpy(r2->arp_tpa, &dst->s_addr, IPLEN);

		p.interface = routelist[idxOfTarget].interface;
		p.len = sizeof(struct ether_header) + sizeof(struct ether_arp);

		memcpy(r2->arp_spa, ip, IPLEN);
		//trimit pachetul pe broadcast
		send_packet(p.interface, &p);
	}
}

//functie care returneaza index-ul destinatiei din tabela arp
int get_index_from_arp_table(struct arp_list *arpl, struct in_addr dst){
	for(int counter = 0 ; counter < arpl->len ; counter++) {
		if(arpl->arplist[counter].ip == dst.s_addr) {
			return counter;
		}
	}
	return -1;
}

int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	uint8_t auxmac[6];
	unsigned long auxip;
	int auxidx;

	queue q;
	q = queue_create();

	int rc;
	int length = 0;
	struct route_table_entry *routelist= parsetable(&length);
	struct arp_list arpl = getArpList();

	init();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)(m.payload);

		//pachetul primit este de tip ARP
		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP){
			struct ether_arp *r = (struct ether_arp*)(m.payload + sizeof(struct ether_header));

			//pachetul primit este un arp-request
			if(ntohs(r->arp_op) == ARPOP_REQUEST){
				arpReply(r, &m, eth_hdr);
			//pachetul primit este un arp-reply
			}else if(ntohs(r->arp_op) == ARPOP_REPLY){
				u_char arp_sha [6];
				get_interface_mac(m.interface, arp_sha);

				if (r->arp_sha != arp_sha){
					//adaug informatia receptionata in tabela arp
					addEntry(r, &arpl);
					//trimit pachetele din coada la destinatie
					while(!queue_empty(q)){
						packet *p = queue_deq(q);
						struct ip *ip = (struct ip *)(p->payload + sizeof(struct ether_header));
						struct in_addr dst = ip->ip_dst;
						auxip = dst.s_addr;
						int idx = get_index_from_arp_table(&arpl, dst);
						//daca este -1 inseamna ca nu am gasit match in tabela de rutare
              			//trimit un mesaj corect sursei
						if(idx != -1){
							int idx = searchRouteTable(&length, &dst, routelist);
							if(idx == -1){
								destinationUnreachable(&m);
							//trimit pachetul din coada la destinatie
							}else{
								get_interface_mac(routelist[idx].interface, auxmac);
								p->interface = routelist[idx].interface;
								struct ether_header *hdr = (struct ether_header *)(p->payload);
								memcpy(hdr->ether_dhost, r->arp_sha, ETH_ALEN);
								send_if_good_check(ip, p);
							}
						}
					}
				}
			}
		//pachetul primit este de tip IP
		}else if (htons(eth_hdr->ether_type) == ETHERTYPE_IP){
			struct ip *ip = (struct ip *)(m.payload + sizeof(struct ether_header));
			struct in_addr src = ip->ip_src, dst = ip->ip_dst, auxaddr;
			char * aux = get_interface_ip(m.interface);

			inet_aton(aux, &auxaddr);

			//daca ttl <=1 trimit un mesaj ICMP completat corect sursei
			if (ip->ip_ttl <= 1) {
				packet r;
				r.len = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr);
				r.interface = m.interface;

				struct ether_header *sender_eth = (struct ether_header *)(r.payload);
				struct iphdr *sender_ip = (struct iphdr *)(r.payload + sizeof(struct ether_header));
				struct icmphdr *sender_icmp = (struct icmphdr *)(r.payload + sizeof(struct ether_header)
					+ sizeof(struct iphdr));

				get_interface_mac(r.interface, sender_eth->ether_shost);
				memcpy(sender_eth->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
				sender_eth->ether_type = eth_hdr->ether_type;
				//completez header-ul ip
				sender_ip->version = 4;
				sender_ip->ihl = 5;
				sender_ip->tos = 0;
				sender_ip->id = 0;
				sender_ip->frag_off = 0;
				sender_ip->tot_len = htons(2 * sizeof(struct iphdr)  + sizeof(struct icmphdr));
				sender_ip->ttl = 255;
				sender_ip->protocol = IPPROTO_ICMP;
				sender_ip->daddr = src.s_addr;
				sender_ip->saddr = dst.s_addr;
				sender_ip->check = 0;
				sender_ip->check = (ip_checksum((void*)(sender_ip), sizeof(struct iphdr)));

				//completez header-ul icmp
				memset(sender_icmp, 0, sizeof(struct icmphdr));
				memcpy(sender_icmp + sizeof(struct icmphdr), ip, sizeof(struct ip));
				sender_icmp->type = 11;
				sender_icmp->code = 0;
				sender_icmp->checksum = 0;
				sender_icmp->checksum = ip_checksum((void*)(sender_icmp), sizeof(struct icmphdr) + sizeof(struct iphdr));
				send_packet(r.interface, &r);
			//ttl>1 => trimit pachetul la destinatie
			} else {
				//daca pachetul nu este destinat router-ului
				if(auxaddr.s_addr != dst.s_addr){
					int idxarp = get_index_from_arp_table(&arpl, dst);
 					//idxarp == -1 => nu am destinatia in tabela arp, fac un arp-request
					if(idxarp == -1){
						void *data = malloc(sizeof(packet));
						memcpy(data, &m, sizeof(packet));
						queue_enq(q, data);
						arpRequest(&m,&length, routelist, eth_hdr, &dst);
					//am destinatia in tabela arp
					}else {
						auxidx = searchRouteTable(&length, &dst, routelist);
						//nu am match in tabela de rutare
						if (auxidx == -1) {
							destinationUnreachable(&m);
						//trimit normal pachetul
						} else {	
							get_interface_mac(routelist[auxidx].interface, auxmac);

							memcpy(eth_hdr->ether_dhost, arpl.arplist[idxarp].mac, 6);
							m.interface = routelist[auxidx].interface;
							send_if_good_check(ip, &m);
						}
					}
				//pachetul este destinat router-ului
				}else{
					packet r;
					r.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
					r.interface = m.interface;

					struct ether_header *sender_eth = (struct ether_header *)(r.payload);
					struct iphdr *sender_ip = (struct iphdr *)(r.payload + sizeof(struct ether_header));
					struct icmphdr *sender_icmp = (struct icmphdr *)(r.payload + sizeof(struct ether_header)
						+ sizeof(struct iphdr));
					get_interface_mac(r.interface, sender_eth->ether_shost);
					memcpy(sender_eth->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
					sender_eth->ether_type = eth_hdr->ether_type;
					//completez header-ul de ip
					sender_ip->version = 4;
					sender_ip->ihl = 5;
					sender_ip->tos = 0;
					sender_ip->id = 0;
					sender_ip->frag_off = 0;
					sender_ip->tot_len = htons(sizeof(struct iphdr)  + sizeof(struct icmphdr));
					sender_ip->ttl = 255;
					sender_ip->protocol = IPPROTO_ICMP;
					sender_ip->check = 0;
					sender_ip->daddr = src.s_addr;
					sender_ip->saddr = dst.s_addr;
					sender_ip->check = (ip_checksum((void*)(sender_ip), sizeof(struct iphdr)));

					//completez header-ul de icmp
					memset(sender_icmp, 0, sizeof(struct icmphdr));
					sender_icmp->type = 0;
					sender_icmp->code = 0;
					sender_icmp->checksum = 0;
					sender_icmp->checksum = ip_checksum((void*)(sender_icmp), sizeof(struct icmphdr));
					send_packet(r.interface, &r);
				}
			}
		}
	}
}