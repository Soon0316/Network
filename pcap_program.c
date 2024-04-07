#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>



struct ethheader {
  u_char  ether_dhost[6]; 
  u_char  ether_shost[6]; 
  u_short ether_type;   
};


struct ipheader {
  unsigned char      iph_ihl:4,
                     iph_ver:4;
  unsigned char      iph_tos;
  unsigned short int iph_len;
  unsigned short int iph_ident; 
  unsigned short int iph_flag:3,
                     iph_offset:13;
  unsigned char      iph_ttl;
  unsigned char      iph_protocol;
  unsigned short int iph_chksum; 
  struct  in_addr    iph_sourceip; 
  struct  in_addr    iph_destip;   
};

struct tcpheader {
  u_int16_t th_sport;
  u_int16_t th_dport;
  u_int32_t seq;
  u_int32_t ack;
  u_int8_t data_offset;
  u_int8_t flags;
  u_int16_t window_size;
  u_int16_t checksum;
  u_int16_t urgent_p;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { 

    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    struct tcpheader * tcp = (struct tcpheader *)
                          (packet +sizeof(struct ethheader) + ip->iph_len);

    printf("         Src MAC: %02x %02x %02x %02x %02x %02x\n", eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
    printf("         Dest MAC: %02x %02x %02x %02x %02x %02x\n", eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]); 
    printf("         Src Ip: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         Dest Ip: %s\n", inet_ntoa(ip->iph_destip)); 
    printf("         Src Port: %d\n",tcp->th_sport );
    printf("         Dest Ip: %d\n", tcp->th_dport);
    printf("         TCP Data size: %d\n", tcp->window_size);
    printf("\n");
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  pcap_compile(handle, &fp, filter_exp, 0, net);
  
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }
  
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   
  return 0;
}
