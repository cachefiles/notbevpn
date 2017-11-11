#ifndef _TCPUP_H_
#define _TCPUP_H_

struct tcpuphdr {  
        tcp_seq th_conv;  
        tcp_seq th_ckpass;  
        tcp_seq th_seq;  
        tcp_seq th_ack;  
#if __BYTE_ORDER == __LITTLE_ENDIAN  
        u_char th_magic: 4;  
        u_char th_opten: 4;  
#else  
        u_char th_opten: 4;  
        u_char th_magic: 4;  
#endif  
        u_char th_flags;  
  
#ifndef TH_FIN  
#  define TH_FIN    0x01  
#  define TH_SYN    0x02  
#  define TH_RST    0x04  
#  define TH_PUSH   0x08  
#  define TH_ACK    0x10  
#  define TH_URG    0x20  
#endif  
  
        u_short th_win;  
};

#define MAGIC_UDP_TCP 0x0E

struct tcpupopt {
        u_int64_t       to_flags;       /* which options are present */
#define TOF_MSS         0x0001          /* maximum segment size */
#define TOF_SCALE       0x0002          /* window scaling */
#define TOF_SACKPERM    0x0004          /* SACK permitted */
#define TOF_TS          0x0010          /* timestamp */
#define TOF_SIGNATURE   0x0040          /* TCP-MD5 signature option (RFC2385) */
#define TOF_SACK        0x0080          /* Peer sent SACK option */
#define TOF_DESTINATION 0x0100          /* Relay target option */
#define TOF_MAXOPT      0x0200         
        u_int32_t       to_tsval;       /* new timestamp */
        u_int32_t       to_tsecr;       /* reflected timestamp */ 
        u_char          *to_sacks;      /* pointer to the first SACK blocks */
        u_char          *to_signature;  /* pointer to the TCP-MD5 signature */
        u_int16_t       to_mss;         /* maximum segment size */
        u_int8_t        to_wscale;      /* window scaling */
        u_int8_t        to_nsacks;      /* number of SACK blocks */
        u_int32_t       to_spare;       /* UTO */
        u_int16_t       to_dslen;       /* relay target to_dsaddr length */
        u_char          *to_dsaddr;     /* relay target to_dsaddr pointer */
};     
       
#define TCPOPT_EOL              0
#define    TCPOLEN_EOL                  1
#define TCPOPT_PAD              0               /* padding after EOL */
#define    TCPOLEN_PAD                  1
#define TCPOPT_NOP              1      
#define    TCPOLEN_NOP                  1      
#define TCPOPT_MAXSEG           2
#define    TCPOLEN_MAXSEG               4
#define TCPOPT_WINDOW           3
#define    TCPOLEN_WINDOW               3
#define TCPOPT_SACK_PERMITTED   4
#define    TCPOLEN_SACK_PERMITTED       2
#define TCPOPT_SACK             5
#define    TCPOLEN_SACKHDR              2
#define    TCPOLEN_SACK                 8       /* 2*sizeof(tcp_seq) */
#define TCPOPT_TIMESTAMP        8
#define    TCPOLEN_TIMESTAMP            10
#define    TCPOLEN_TSTAMP_APPA          (TCPOLEN_TIMESTAMP+2) /* appendix A */
#define TCPOPT_SIGNATURE        19              /* Keyed MD5: RFC 2385 */
#define    TCPOLEN_SIGNATURE            18

#define TCPOPT_DESTINATION      63              /* tcpup telay destination */
#define    TCPOLEN_DESTINATION          2

struct sackblk {
        tcp_seq start;          /* start seq no. of sack block */
        tcp_seq end;            /* end seq no. */
};     

int tcpip_dooptions(struct tcpupopt *to, u_char *cp, int cnt);
int tcpip_addoptions(struct tcpupopt *to, u_char *cp);

int tcpup_dooptions(struct tcpupopt *to, u_char *cp, int cnt);
int tcpup_addoptions(struct tcpupopt *to, u_char *cp);

#define TCPUP_PROTO_UDP 0xfe800001
#define TCPUP_PROTO_DNS 0xfe800000

int tcpup_track_stage1(void);
int tcpup_track_stage2(void);
ssize_t udpup_frag_input(void *packet, size_t len, uint8_t *buf, size_t limit);
ssize_t udpip_frag_input(void *packet, size_t len, uint8_t *buf, size_t limit);

unsigned tcpip_checksum(unsigned cksum,  const void *buf, size_t len, int finish);
int udp_checksum(unsigned cksum, void *buf, size_t len);
int tcp_checksum(unsigned cksum, void *buf, size_t len);
int ip_checksum(void *buf, size_t len);
#endif
