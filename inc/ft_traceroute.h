#ifndef TRACE_HEADER
#define TRACE_HEADER

#include "../libft/libft.h"

#include <limits.h>

#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <arpa/inet.h>

#include <sys/time.h>

#include <errno.h>

#include <netinet/ip_icmp.h>
#include <string.h>

#include <netinet/in.h>

#define PING_PKT_S 8192 // max ping size but irl max is 8184



// //from ip_icmp.h

#define ICMP_ECHO                8        /* Echo Request     */
#define ICMP_ECHOREPLY          0               /* echo reply */
#define ICMP_UNREACH            3               /* dest unreachable, codes: */
#define ICMP_TIMXCEED           11              /* time exceeded, code: */


struct s_icmphdr
{
  u_int8_t type;                /* message type */
  u_int8_t code;                /* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t        id;
      u_int16_t        sequence;
    } echo;                        /* echo datagram */
    u_int32_t        gateway;        /* gateway address */
    struct
    {
      u_int16_t        unused;
      u_int16_t        mtu;
    } frag;                        /* path mtu discovery */
  } un;
};

typedef struct 
{ 
    uint8_t   ver_hlen;   /* Header version and length (dwords). */
    uint8_t   service;    /* Service type. */
    uint16_t  length;     /* Length of datagram (bytes). */
    uint16_t  ident;      /* Unique packet identification. */
    uint16_t  fragment;   /* Flags; Fragment offset. */
    uint8_t   timetolive; /* Packet time to live (in network). */
    uint8_t   protocol;   /* Upper level protocol (UDP, TCP). */
    uint16_t  checksum;   /* IP header checksum. */
    uint32_t  src_addr;   /* Source IP address. */
    uint32_t  dest_addr;  /* Destination IP address. */

} NetIpHdr;

// struct msghdr {
//     void         *msg_name;       /* optional address */
//     socklen_t     msg_namelen;    /* size of address */
//     struct iovec *msg_iov;        /* scatter/gather array */
//     size_t        msg_iovlen;     /* # elements in msg_iov */
//     void         *msg_control;    /* ancillary data, see below */
//     size_t        msg_controllen; /* ancillary data buffer len */
//     int           msg_flags;      /* flags on received message */
// };

/////////////////////////////////////////////////////////

struct   ping_pkt{
    struct s_icmphdr hdr;
    char msg[PING_PKT_S-sizeof(struct s_icmphdr)];
};

// struct addrinfo {
//                int              ai_flags;
//                int              ai_family;
//                int              ai_socktype;
//                int              ai_protocol;
//                socklen_t        ai_addrlen;
//                struct sockaddr *ai_addr;
//                char            *ai_canonname;
//                struct addrinfo *ai_next;
// };

// struct sockaddr
// {
//     unsigned short integer sa_family;     /* address family */
//     char sa_data[14];      /*  up to 14 bytes of direct address */
// };

// struct sockaddr_in {
//     short            sin_family;   // e.g. AF_INET
//     unsigned short   sin_port;     // e.g. htons(3490)
//     struct in_addr   sin_addr;     // see struct in_addr, below
//     char             sin_zero[8];  // zero this if you want to
// };

// struct in_addr {
//     unsigned long s_addr;  // load with inet_aton()
// };

struct          time_s{
  struct timeval      Timeval; // struct timeval {
                                  //    time_t      tv_sec;     /* seconds */
                                  //    suseconds_t tv_usec;    /* microseconds */
                                  // };
  struct timezone     Timezone; // struct timeval {
                                    //    int tz_minuteswest;     /* minutes west of Greenwich */
                                    //    int tz_dsttime;         /* type of DST correction */
                                    // };
};

struct                  s_count_flag{
  short                 enabler;
  long long             value;
};
typedef struct          s_ping{
    int                 pong; // ping.pong comtroled by signal
    int                 sockfd;
    int                 verbose;
    int                 sent_count;
    int                 rcev_count;
    int                 errors;
    int                 interval_flag;
    int                 flood_flag;
    struct s_count_flag count_flag; // 0 there is a count flag -c, 1 is the count value 
    int                 ttl;
    size_t              msg_size;
    size_t              sizeof_pkt;
    char                *host_av_addr;
    char                ipStr[INET_ADDRSTRLEN];
    u_int16_t           s_seq;
    u_int16_t           pid;
    double              rtt_stats[3]; // 0 min, 1 max, 2 total to calculate avg
    struct ping_pkt     s_pkt;
    struct ping_pkt     *r_pkt;
    struct msghdr       r_msg;
    struct addrinfo     addrInfoStruct; // struct addrinfo {
                                        //    int              ai_flags;
                                        //    int              ai_family;
                                        //    int              ai_socktype;
                                        //    int              ai_protocol;
                                        //    socklen_t        ai_addrlen; 
                                        //    struct sockaddr *ai_addr;
                                        //    char            *ai_canonname;
                                        //    struct addrinfo *ai_next;
                                        // };
    struct addrinfo     *addrInfo; 
    struct time_s       GlobaltimeCount[2]; // 0 start , 1 stop
    struct time_s       timeCount[2]; // 0 sent , 1 received
    struct timeval      rcvTimeval; // struct timeval {
                                    //    time_t  tv_sec;
                                    //    suseconds_t  tv_usec;
                                    // };
}                       t_ping;

#endif