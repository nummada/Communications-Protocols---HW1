#include "myparser.h"

//functie care realizeaza parsarea tabelei de rutare
struct route_table_entry* parsetable(int* count){
	int maxLength = 64500;
	struct route_table_entry *list = malloc(maxLength * sizeof(struct route_table_entry));

	FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen("rtable.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, fp)) != -1) {
	    char *token = strtok(line, " .");

		while(token != NULL){
			list[*count] = parseALine(token);
			*count = *count + 1;
			if(*count >= maxLength){
				list = realloc(list, sizeof(struct route_table_entry) * maxLength * 2);
				maxLength *= 2;
			}
			token = strtok(NULL, " .");
		}
    }

    fclose(fp);
    return list;
}

//functie care aloca tabela de rutare
struct route_table_entry* getRouteTableEntry(){
	struct route_table_entry *rout = malloc(sizeof(struct route_table_entry));
	rout->prefix = 0;
	rout->next_hop = 0;
	rout->mask = 0;
	rout->interface = 0;

	return rout;
}


//functie care parseaza o linie din fisierul de input
struct route_table_entry parseALine(char* token){
	uint32_t prefix = 0;
	uint32_t next_hop = 0;
    uint32_t mask = 0;
    int interface = 0;
    struct route_table_entry rout = *getRouteTableEntry();

		for(int i = 0 ; i < 4 ; i++){
			rout.prefix = rout.prefix << 8;
			prefix = atoi(token);
			rout.prefix = rout.prefix | prefix;
			token = strtok(NULL, " .");
		}
		for(int i = 0 ; i < 4 ; i++){
			rout.next_hop = rout.next_hop << 8;
			next_hop = atoi(token);
			rout.next_hop = rout.next_hop | next_hop;
			token = strtok(NULL, " .");
		}
		for(int i = 0 ; i < 4 ; i++){
			rout.mask = rout.mask << 8;
			mask = atoi(token);
			rout.mask = rout.mask | mask;
			token = strtok(NULL, " .");
		}
	interface = atoi(token);
	rout.interface = interface;
	return rout;
}

