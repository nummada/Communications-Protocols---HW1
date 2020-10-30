#ifndef PARSER
#define PARSER

#include "./include/skel.h"

//structura unei intrari in tabela de rutare
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct route_table_entry* parsetable(int* count);
struct route_table_entry* getRouteTableEntry();
struct route_table_entry parseALine(char* token);

#endif