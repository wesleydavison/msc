#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

pcap_t *handle;				/* packet capture handle */
pcap_t *handle_dead;
char *inFileName;           /* trace input */
pcap_dumper_t *outHandle; 
const char *outFileName;          /* trace output */
FILE *outFile;
struct pcap_file_hdr* descr;

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct pseudo_tcp_header
{
    //unsigned int ip_src;
    //unsigned int ip_dst;
    struct in_addr ip_src;
    struct in_addr ip_dst;
    unsigned char zero;//always zero
    unsigned char protocol;// = 6;//for tcp
    unsigned short tcp_len;
};

struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */

};
#define SIZE_UDP        8               /* length of UDP header */

struct pcap_file_hdr {
	int magic;
	u_short version_major;
	u_short version_minor;
	int thiszone;	/* gmt to local correction */
	int sigfigs;	/* accuracy of timestamps */
	int snaplen;	/* max length saved portion of each pkt */
	int linktype;	/* data link type (LINKTYPE_*) */
};


struct pcap_packet_hdr {
        int tv_sec;
        int tv_usec;
        int caplen;     /* length of portion present */
        int len;        /* length this packet (off wire) */
};

void
got_packet(u_char *outHandle, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

uint16_t calcIPChecksum(struct sniff_ip* header);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

void checkHeader(struct pcap_file_hdr *descr){
    if(descr->magic != 0xA1B2C3D4){
        descr->magic = 0xA1B2C3D4;
    }
    if(descr->version_major != 2){
        descr->version_major = 2;
    }
    if(descr->version_minor != 4){
        descr->version_minor = 4;
    }
    if(descr->snaplen != 0xFFFF){
        descr->snaplen = 0xFFFF;
    }
    if(descr->linktype != 1){
        descr->linktype = 1;
    }
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

uint16_t calcIPChecksum(struct sniff_ip* header)
{
    // clear existent IP header
    header->ip_sum = 0x0;

    // calc the checksum
    unsigned int nbytes = sizeof(struct sniff_ip);
    unsigned short *buf = reinterpret_cast<unsigned short *>( header );
    unsigned int sum = 0;
    for (; nbytes > 1; nbytes -= 2){
        sum += *buf++;
    }
    if (nbytes == 1){
        sum += *(unsigned char*) buf;
    }
    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    //header->ip_sum = ~sum;

    return ~sum;
}


uint16_t calcTCPChecksum(struct pseudo_tcp_header *header)
{

    // calc the checksum
    unsigned int nbytes = sizeof(struct pseudo_tcp_header);
    unsigned short *buf = reinterpret_cast<unsigned short *>( header );
    unsigned int sum = 0;
    for (; nbytes > 1; nbytes -= 2){
        sum += *buf++;
    }
    if (nbytes == 1){
        sum += *(unsigned char*) buf;
    }
    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    //header->ip_sum = ~sum;

    return ~sum;
}

void updateHeader(u_char *orig_pkt, u_char *new_pkt,int size_ip, int size_transp, int size_payload ){

    /* updating  header pointers */
	struct sniff_ethernet *orig_ethernet; 
	struct sniff_ethernet *new_ethernet; 
	struct sniff_ip *orig_ip;             
	struct sniff_ip *new_ip;             
	struct sniff_tcp *orig_tcp;           
	struct sniff_tcp *new_tcp;           
    struct sniff_udp *orig_udp;
    struct sniff_udp *new_udp;
	char *orig_payload;                   
	char *new_payload;                   

    //filling ethernet header
	/*orig_ethernet = (struct sniff_ethernet*)(orig_pkt);
	new_ethernet = (struct sniff_ethernet*)(new_pkt);
    new_ethernet->ether_dhost = orig_ethernet->ether_dhost;
    new_ethernet->shost = orig_ethernet->ether_shost;
    new_ethernet->ether_type = orig_ethernet_ether_arp;
    */

    //filling IP header
	orig_ip = (struct sniff_ip*)(orig_pkt + SIZE_ETHERNET);
	new_ip = (struct sniff_ip*)(new_pkt + SIZE_ETHERNET);
    new_ip->ip_vhl = orig_ip->ip_vhl;
    new_ip->ip_tos = orig_ip->ip_tos;
    new_ip->ip_len = size_ip + size_transp + size_payload; 
    new_ip->ip_id = orig_ip->ip_id;
    new_ip->ip_off = orig_ip->ip_off;
    new_ip->ip_ttl = orig_ip->ip_ttl;
    new_ip->ip_p = orig_ip->ip_p;
    new_ip->ip_src = orig_ip->ip_src;
    new_ip->ip_dst = orig_ip->ip_dst;
    new_ip->ip_sum = calcIPChecksum(new_ip);


	switch(orig_ip->ip_p) {
		case IPPROTO_TCP:
            orig_tcp = (struct sniff_tcp*)(orig_pkt + SIZE_ETHERNET + size_ip);
            new_tcp = (struct sniff_tcp*)(new_pkt + SIZE_ETHERNET + size_ip);
            /*struct pseudo_tcp_header *pseudo_hdr = (struct pseudo_hdr *) malloc (sizeof (struct pseudo_tcp_header)); 
            pseudo_hdr->ip_src = orig_ipl;
            pseudo_hdr->ip_dst = orig_tcp->th_d
            uint16_t new_sum = calcTCPChecksum(
            printf("orig_tcp sum: %u and calc sum*/ 
			break;
		case IPPROTO_UDP:
            orig_udp = (struct sniff_udp*)(orig_pkt + SIZE_ETHERNET + size_ip);
            new_udp = (struct sniff_udp*)(new_pkt + SIZE_ETHERNET + size_ip);
			break;
		default:
            //ERROR
			return;
	}

	orig_payload = (u_char *)(orig_pkt + SIZE_ETHERNET + size_ip + size_transp);
	new_payload = (u_char *)(new_pkt + SIZE_ETHERNET + size_ip + size_transp);
    
    

}

u_char *padding_packet( const u_char *orig_pkt,int pkt_number, int hdrlen ,int total_len, int caplen){
    
    u_char *pk;
    pk = (u_char *) orig_pkt;
    u_char *new_pkt = (u_char *) malloc(total_len); 

    memset(new_pkt,'\x20', total_len);//TODO remove after checking
    memcpy(new_pkt, pk, caplen);
    

    
    /* filling payload */
    int size_padding = 0;
    if( total_len < caplen ){
        return new_pkt; //pkt is just filled
    }

    else{
        size_padding = total_len - caplen;
    }
    
    int i;
    u_char *to_fill = (u_char *)(new_pkt + caplen);
    for(i = 0; i < size_padding; i++){
        memcpy(&(to_fill[i]), "\x31", 1);//new payload
    }

    return new_pkt;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *outHandleParam, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
    const struct sniff_udp *udp;
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
    int size_transp;
	int size_payload;
	
    //printf("\nPacket number %d:\n", count);
	count++;
	
	ethernet = (struct sniff_ethernet*)(packet);
	
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
        //pcap_dump((u_char*)outHandle,header,packet);
        //pcap_dump_flush(outHandle);
		return;
	}

	switch(ip->ip_p) {
		case IPPROTO_TCP:
            //printf("PROTO IS TCP\n");
	
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            size_transp = size_tcp;
            if (size_tcp < 20) {
                //printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                //pcap_dump((u_char*)outHandle,header,packet);
                //pcap_dump_flush(outHandle);
                return;
            }
			break;
		case IPPROTO_UDP:
            //printf("PROTO IS UDP\n");
            size_transp = SIZE_UDP;
			break;
		default:
            //pcap_dump((u_char*)outHandle,header,packet);
            //pcap_dump_flush(outHandle);
			return;
	}
	
	
	
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_transp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_transp);
    //printf("size_payload is %d\n", size_payload);
	
    int caplen = header->caplen;
    int hdrlen =  SIZE_ETHERNET + size_ip + size_transp;
	if (size_payload > 0) {
        
        u_char *new_pkt = padding_packet(packet, count, hdrlen, hdrlen+size_payload, caplen); 
        //updateHeader(packet, new_pkt, size_ip,  size_transp, size_payload);
        struct pcap_packet_hdr *new_pcap_hdr = (struct pcap_packet_hdr *) malloc(16); 
        new_pcap_hdr->caplen = hdrlen+size_payload;
        new_pcap_hdr->len = hdrlen+size_payload;
        new_pcap_hdr->tv_sec = header->ts.tv_sec;
        new_pcap_hdr->tv_usec = header->ts.tv_usec;

        //fwrite(new_pcap_hdr,1,sizeof(struct pcap_packet_hdr),outFile);
        fwrite(new_pcap_hdr,4,4,outFile);
        fwrite(new_pkt,1,new_pcap_hdr->len,outFile);
        
        //printf("------ packet %d ------- \n", count);
        //print_payload(new_pkt,SIZE_ETHERNET + size_ip + size_transp + size_payload);
        //printf("-- only payload --\n");
        //payload = (u_char *)(new_pkt + SIZE_ETHERNET + size_ip + size_transp);
        //print_payload(payload,size_payload);
        //printf("\n\n");
        
        free(new_pkt);
        free(new_pcap_hdr);
	}
    

    //return;
}

void printHelp( char *progname ){

	fprintf( stderr, "%s version 1.0\n", progname);
	fprintf( stderr, "Usage: %s [-h] [-i interface] [-r input file] [-q number of threads] \n"
			"where\n"
			"-h: this message\n"
            "-r: Input file to offline capture\n"
			"-s: Capture snaplen\n"
			"-w: Output filename\n", progname);
            
}

void taskCtrl_C(int i)
{
	/* cleanup */
	pcap_close(handle);
    pcap_dump_close(outHandle);
    printf("finished capture by ctrl-c\n");
}

int main(int argc, char **argv)
{
	//signal(SIGINT, taskCtrl_C);
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    inFileName = (char *) malloc(sizeof(char)*100);
    //outFileName = (char *) malloc(sizeof(char)*100);
    outFileName[100];
    int snapLen = 1518;

	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 10;			/* number of packets to capture */

	print_app_banner();

    int c;
	while ((c = getopt(argc, argv, "hr:s:w:")) != -1){
		switch (c) {
		case 'r':
			inFileName = optarg;
			break;
		case 's':
			snapLen = atoi(optarg);
			break;
		case 'w':
			outFileName = optarg;
			break;
		case 'h':
			printHelp( argv[0] );
			return 0;
		case '?':
			if (isprint(optopt)){
				fprintf(stderr, "Unknown option '-%c'.\n", optopt);
				fprintf(stderr, "Use \"%s -h\" to see valid options\n", argv[0] );
			} else {
				fprintf(stderr,	"Unknown option character '\\x%x'.\n", optopt);
				fprintf(stderr, "Use \"%s -h\" to see valid options\n", argv[0] );
			}
			return 1;
		default:
			abort();
		}
	}


    handle= pcap_open_offline(inFileName,errbuf);
	if(!handle) {
		printf("ERROR! Could not open input trace file %s\npcap error: %s\n", inFileName, errbuf);
		return NULL;
	}

    outFile = fopen(outFileName,"wb") ;
    if(outFile == NULL){
        printf("ERROR! Fail to open file %s: error is %s\n", outFileName, strerror(errno));
        return -1;
    }

    descr = (struct pcap_file_hdr *) malloc(sizeof(struct pcap_file_hdr));
    checkHeader(descr);
    fwrite(descr, 4, 6, outFile);

    
    pcap_loop(handle, 0, got_packet, NULL);   
    fclose(outFile);
    //pcap_dump_close(outHandle);
    return 0;
}

