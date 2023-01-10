#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}


typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

typedef struct Node{
	struct Node *next;

    u_int8_t BSS_ID[6];

	int beacons;
	u_int8_t    tag_length;
	char* SSID;
}Node;


struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct beacon_frame{
    u_int8_t    subtype;
    u_int8_t    flags;

    u_int16_t   duration;

    u_int8_t DA[6];
    u_int8_t SA[6];
    u_int8_t BSS_ID[6];
    
    u_int16_t   fragment_sequence_number;

} __attribute__((__packed__));

struct necessary_field{

    u_int8_t   timestamp[8];

    u_int16_t   interval;

    u_int16_t   capacity_information;

    u_int8_t    tag_number;
    u_int8_t    tag_length;


} __attribute__((__packed__));


struct tcp_hdr* get_radiotap_header(const u_char* data){
	struct tcp_hdr *tcp_header = (struct tcp_hdr *)data;

	return tcp_header;
}


bool search_beacon(Node *node, u_int8_t BSS_ID[]){
	while(node != NULL){
		if(!memcmp(BSS_ID, node->BSS_ID, 6)){
			node->beacons += 1;
			return true;
		}
		node = node->next;	
	}

	return false;
}

void add_node(Node *node, Node *new_node ){
	
	while(node->next != NULL)
		node = node->next;
	new_node->beacons += 1;	
	new_node->next = NULL;
	node->next = new_node;

	return ;
}
	
void node_print(Node *node){
	int line = 0;
	node = node->next;
	move(line,0);
	printw("BSSID                 Beacons           ESSID\n");
	line += 1;
	while(node != NULL){
		move(line,0);
		printw("%02x:%02x:%02x:%02x:%02x:%02x",node->BSS_ID[0], node->BSS_ID[1], node->BSS_ID[2], node->BSS_ID[3], node->BSS_ID[4], node->BSS_ID[5]);
		move(line,25);
		printw("%d", node->beacons);
		move(line,40);
		if(node->SSID[0]==0)
			printw("<length: %d>", node->tag_length);
		else
			printw("%s\n", node->SSID);
		refresh();
		// sleep(0.5);
		node = node->next;
		line += 1;
	}
}



int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	
	Node *head = malloc(sizeof(Node));
	head -> next = NULL;

	initscr();
	while(true){
		move(0,0);
		Node *node = malloc(sizeof(Node));
		
		struct pcap_pkthdr* header;
		const u_char* packet;	

		struct ieee80211_radiotap_header* radiotap_header;
		struct beacon_frame* beacon;
		struct necessary_field* nf;

		int res = pcap_next_ex(pcap, &header, &packet);

		
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			return 0;
		}
		radiotap_header = packet;

		beacon = packet + radiotap_header->it_len;
		
		nf = packet + radiotap_header->it_len + sizeof(struct beacon_frame);

		node->SSID = (char*)malloc(sizeof(char) * nf->tag_length);

		memcpy(node->SSID, packet+radiotap_header->it_len + sizeof(struct beacon_frame) + sizeof(struct necessary_field) , nf->tag_length);
		memcpy(node->BSS_ID,beacon->BSS_ID, 6);
		node->beacons = 0;
		node->tag_length = nf->tag_length;

		if(beacon->subtype == 0x80){
			if(search_beacon(head, node->BSS_ID)){}
			else{
				add_node(head,node);
			}
			node_print(head);
		}
	}
	
	pcap_close(pcap);
	return 0;
}
