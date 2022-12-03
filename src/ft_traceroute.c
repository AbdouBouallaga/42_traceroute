#include "../inc/ft_traceroute.h"

t_tR tR;

unsigned short checksum(void *b, int len){ // Calculating icmp CheckSum
    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;
 
    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
{
        const uint16_t *buf=buff;
        uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
        uint32_t sum;
        size_t length=len;
 
        // Calculate the sum                                            //
        sum = 0;
        while (len > 1)
        {
                sum += *buf++;
                if (sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                len -= 2;
        }
 
        if ( len & 1 )
                // Add the padding if the packet lenght is odd          //
                sum += *((uint8_t *)buf);
 
        // Add the pseudo-header                                        //
        sum += *(ip_src++);
        sum += *ip_src;
 
        sum += *(ip_dst++);
        sum += *ip_dst;
 
        sum += htons(IPPROTO_UDP);
        sum += htons(length);
 
        // Add the carries                                              //
        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);
 
        // Return the one's complement of sum                           //
        return ( (uint16_t)(~sum)  );
}
// 

void init_ping(){ // init ping struct
    ft_bzero(&tR.addrInfo, sizeof(struct addrinfo));
    tR.pong = 1;
    tR.verbose = 0;
    tR.msg_size = 32;
    tR.interval_flag = 1;
    tR.flood_flag = 0;
    tR.count_flag.enabler = 0; //flag -c enabler
    tR.count_flag.value = 0; //flag -c value
    tR.sent_count = 0;
    tR.rcev_count = 0;
    tR.ttl = 1;
    ///
    tR.max_hops = 29;
    tR.last_addr = 0;
    tR.hop = 1;
    tR.last_hop = 0;
    ///
    tR.rtt_stats[0] = INT16_MAX; // min
    tR.rtt_stats[1] = 0; // max
    tR.rtt_stats[2] = 0; // total
    tR.rcvTimeval.tv_sec = 0;  /* 3 Secs Timeout */
    tR.rcvTimeval.tv_usec = 300000;  /* 3 Secs Timeout */
    tR.addrInfo = &tR.addrInfoStruct;
    tR.sizeof_pkt = (sizeof(tR.s_pkt)-sizeof(tR.s_pkt.msg)) + tR.msg_size;
    tR.pid = getpid();
    tR.protocol = 1;
    tR.sockfd_send_proto = IPPROTO_UDP;
}

void    halt(){
    freeaddrinfo(tR.addrInfo);
    exit(1);
}

void    statsSave(double time){
    if (tR.rtt_stats[0] > time) // min
        tR.rtt_stats[0] = time;
    if (tR.rtt_stats[1] < time) // max
        tR.rtt_stats[1] = time;
    tR.rtt_stats[2] += time; // total
}

void    prepare_s_pkt_icmp(){
    int i;
    ft_bzero(&tR.s_pkt, tR.sizeof_pkt);
    //// fillup icmp packet ////
    // set packet type to ICMP_ECHO
    tR.s_pkt.hdr.type = ICMP_ECHO;
    // set id to pid of process
    tR.s_pkt.hdr.un.echo.id = tR.pid;
    // fill msg (random)
    i = -1;
    if (tR.msg_size){
        while(++i < (int)tR.msg_size){
            tR.s_pkt.msg[i] = 'Z';
        }
        tR.s_pkt.msg[i] = '\0';
    }
    // fill sequance number
    tR.s_pkt.hdr.un.echo.sequence = tR.s_seq;
    // calculate checksum
    tR.s_pkt.hdr.checksum = checksum(&tR.s_pkt, tR.sizeof_pkt);
}

void    prepare_s_pkt_udp(){
    int i;
    ft_bzero(&tR.s_pkt, tR.sizeof_pkt);
    //// fillup udp packet ////
    ((struct s_udphdr *)&tR.s_pkt.hdr)->source_port = htons(tR.pid);
    ((struct s_udphdr *)&tR.s_pkt.hdr)->dest_port = htons(33434);
    ((struct s_udphdr *)&tR.s_pkt.hdr)->len = htons(tR.sizeof_pkt);
    ((struct s_udphdr *)&tR.s_pkt.hdr)->check = 0;

}



void    trace_write(){
    uint8_t *r_ip;
    char    *tmp;        
    char ip[INET_ADDRSTRLEN];
    struct addrinfo addrInfotmp;
    struct addrinfo *addrptr;
    addrptr = &addrInfotmp;
    ft_bzero(ip, INET_ADDRSTRLEN);
    if (tR.last_addr != tR.r_ipHdr->src_addr){
        r_ip = (uint8_t *)&tR.r_ipHdr->src_addr;
        tR.last_addr = tR.r_ipHdr->src_addr;
        int i = -1;
        while(++i < 4){
            tmp = ft_itoa(r_ip[i]);
            ft_strcat(ip, tmp);
            free(tmp);
            if (i < 3)
                ft_strcat(ip, ".");
        }
        int p = getaddrinfo(ip, NULL, NULL, &addrptr);
        ft_bzero(&tR.fqdn, sizeof(tR.fqdn));
        int y = getnameinfo(addrptr->ai_addr,sizeof(struct sockaddr),tR.fqdn,sizeof(tR.fqdn),0,0,0);
        if (y != 0){
            printf("getnameinfo failed %s\n", gai_strerror(y));
            exit(1);
        }
        if (tR.hop == tR.last_hop)
            printf("\n  ");
        else {
            tR.last_hop = tR.hop;
            printf(" %d", tR.hop);
        }
        printf(" %s (%d.%d.%d.%d)", tR.fqdn, r_ip[0], r_ip[1], r_ip[2], r_ip[3]);
        while (tR.errors){
            printf("  *");
            tR.errors = 0;
        }
    }
}

void    pingPong(){
    int loop;
    int rcv;
    int wind = 0;
    NetIpHdr            *temp_ipHdr;
    // NetIpHdr *r_ipHdr;
    // uint8_t *r_ip; // uint32_t / 4, x.x.x.x
    if (tR.protocol)
        prepare_s_pkt_udp();
    else
        prepare_s_pkt_icmp();
    char msg[92];
    ft_bzero(&tR.r_msg, sizeof(tR.r_msg));
    
    // get send time
    gettimeofday(&tR.timeCount[0].Timeval, NULL);
    // send the packet
    int snt = 0;
    snt = sendto(tR.sockfd_send, &tR.s_pkt, (size_t)tR.sizeof_pkt, 0, tR.addrInfo->ai_addr, sizeof(*tR.addrInfo->ai_addr));
    if (snt == -1){
        printf("sendto : %s\n", strerror(errno));
        goto out;
    }

    tR.s_seq += (u_int16_t)1;

    loop = 1;

    while (loop){ // to ignore all indesired icmp packets  >> if (tR.r_pkt->hdr.un.echo.id != tR.s_pkt.hdr.un.echo.id){
        rcv = recvfrom(tR.sockfd_recv, &msg, sizeof(msg), 0, NULL, NULL);
            if (rcv == -1){
                tR.errors++;
                if (tR.errors > 2){
                    printf("\t*\t*\t*");
                    tR.errors = 0;
                }
                loop = 0;
            }
        // }
        else {
            tR.r_ipHdr = (NetIpHdr *)msg;
            tR.r_pkt = (struct pkt *)&msg[sizeof(NetIpHdr)];
            gettimeofday(&tR.timeCount[1].Timeval, NULL);
            double time = (tR.timeCount[1].Timeval.tv_usec - tR.timeCount[0].Timeval.tv_usec)/1000.0+(tR.timeCount[1].Timeval.tv_sec - tR.timeCount[0].Timeval.tv_sec)*1000.0;
            statsSave(time);
            if (tR.r_pkt->hdr.type == ICMP_ECHOREPLY){
                if(tR.max_hops > 3)
                    tR.max_hops = 3;
                if (tR.r_pkt->hdr.un.echo.id != tR.s_pkt.hdr.un.echo.id){
                    goto end;
                }
                trace_write();
                printf("  %.3fms", time);
                loop = 0;
                tR.max_hops--;
            }
            else if (tR.r_pkt->hdr.type == ICMP_TIMXCEED){// type 11 have 8 bytes then contain ip and icmp header
                tR.r_pkt = (struct pkt *)&msg[(sizeof(NetIpHdr)*2+8)];
                if (tR.r_pkt->hdr.un.echo.id != tR.s_pkt.hdr.un.echo.id)
                    goto end;
                trace_write();
                printf("  %.3fms", time);
                loop = 0;
            }
            else {
                tR.r_pkt = (struct pkt *)&msg[(sizeof(NetIpHdr)*2+8)];
                temp_ipHdr = (NetIpHdr *)&msg[(sizeof(NetIpHdr)+8)];
                if (tR.r_ipHdr->src_addr == temp_ipHdr->dest_addr){
                    if(tR.max_hops > 3)
                        tR.max_hops = 3;
                    tR.max_hops--;
                }
                if (tR.r_pkt->hdr.un.echo.id != tR.s_pkt.hdr.un.echo.id)
                    goto end;
                trace_write();
                printf("  %.3fms", time);
                loop = 0;
            }
        end:
        continue;
        }
    }
    out:
    tR.pong = 1;
    // printf("ttl = %d ", tR.ttl);
}

void    usage(char *execName){
    printf("Usage:\n\t %s [options] <host>\n", execName);
    printf("Options:\n");
    printf("\t-I  --icmp\t\t\t\tUse ICMP ECHO for tracerouting\n");
    printf("\t-m max_ttl \t\t\tSet the max number of hops (max TTL to be\n\t\t\t\t\t\treached). Default is 30\n");
    exit(0);
}

int ft_itsdigit(char *str){
    int i = -1;
    while(str[++i]){
        if (!ft_isdigit(str[i]))
            return (0);
    }
    return (1);
}

int main(int ac, char **av){

    int i; // av index
    int dns; // dns check and msg fill
    struct addrinfo hints;



    if (getuid() != 0){
        printf("Please run as root\n");
        exit(1);
    }
    if(ac < 2)
	{
		usage(av[0]);
	}
    init_ping();
    i = 1;
    while(av[i] && av[i][0] == '-' && i < ac){
        if (av[i][1] == 'v'){
            tR.verbose = 1;
        }
        else if (av[i][1] == 'I' || !ft_strcmp(av[i], "-icmp")){
            tR.protocol = 0;
            tR.sockfd_send_proto = IPPROTO_ICMP;
            tR.msg_size = 56;
        }
        else if ((av[i][1] == 'm') && ft_itsdigit(av[i+1])){
            tR.max_hops = ft_atoi(av[i+1])-1;
            if (tR.max_hops< 0){
                printf("first hop out of range\n");
                exit(1);
            }
            i++;
        }
        else if (av[i][1] == 'h'){
            usage(av[0]);
        }
        else{
            printf("Invalid option: %s\n", av[i]);
            usage(av[0]);
        }
        i++;
    }
    if (av[i] == NULL){
        usage(av[0]);
    }
    // set ping package size
    tR.sizeof_pkt = sizeof(tR.s_pkt)-sizeof(tR.s_pkt.msg) + tR.msg_size;

    dns = getaddrinfo(av[i], NULL, NULL, &tR.addrInfo);
    if (dns != 0){
        printf("%s: %s , <destination> error : %s\n", av[0], av[i], gai_strerror(dns));
        exit(1);
    }
    inet_ntop(tR.addrInfo->ai_family, &((struct sockaddr_in *) tR.addrInfo->ai_addr)->sin_addr, tR.ipStr, INET_ADDRSTRLEN);
    tR.sockfd_send = socket(AF_INET, SOCK_RAW, tR.sockfd_send_proto);
    tR.sockfd_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (tR.sockfd_send < 1 || tR.sockfd_recv < 1){
        printf("socket error\n");
        exit(1);
    }
    // set Time to live (ttl) to limit hops of the packert
    if (setsockopt(tR.sockfd_send, IPPROTO_IP, IP_TTL, &tR.ttl, sizeof(tR.ttl)) != 0){
        printf("setsockopt IP_TTL %s\n", strerror(errno));
    }
    // set socket receive timeout
    if (setsockopt(tR.sockfd_send, SOL_SOCKET, SO_RCVTIMEO, &tR.rcvTimeval, sizeof(tR.rcvTimeval)) != 0){
        printf("setsockopt SO_RCVTIMEO %s\n", strerror(errno));
    }
    if (setsockopt(tR.sockfd_recv, SOL_SOCKET, SO_RCVTIMEO, &tR.rcvTimeval, sizeof(tR.rcvTimeval)) != 0){
        printf("setsockopt SO_RCVTIMEO %s\n", strerror(errno));
    }
    tR.host_av_addr = av[i]; // save the host name memory address
    printf("traceroute to %s (%s), %d hops max, %d byte packets\n", tR.host_av_addr, tR.ipStr, tR.max_hops+1, tR.sizeof_pkt);
    // gettimeofday(&tR.GlobaltimeCount[0].Timeval, NULL);
    signal(SIGINT, halt); // ctrl+c signal
    pingPong();
    int count = 1;
    while (1){
        if (tR.pong){
            if (!(count % 3)){
                printf("\n");
                tR.hop++;
                tR.ttl++;
                tR.max_hops--;
                if (setsockopt(tR.sockfd_send, IPPROTO_IP, IP_TTL, &tR.ttl, sizeof(tR.ttl)) != 0){
                    printf("setsockopt IP_TTL %s\n", strerror(errno));
                }
            }
            count++;
            tR.pong = 0;
            pingPong();
            if (tR.max_hops == 0){
                halt();
            }
        }
    }
    return(0);
}
