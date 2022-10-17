#include "../inc/ft_traceroute.h"

t_ping ping;

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
// 

void init_ping(){ // init ping struct
    ping.pong = 1;
    ping.verbose = 0;
    ping.msg_size = 56;
    ping.interval_flag = 1;
    ping.flood_flag = 0;
    ping.count_flag.enabler = 0; //flag -c enabler
    ping.count_flag.value = 0; //flag -c value
    ping.sent_count = 0;
    ping.rcev_count = 0;
    ping.ttl = 30;
    ping.rtt_stats[0] = INT16_MAX; // min
    ping.rtt_stats[1] = 0; // max
    ping.rtt_stats[2] = 0; // total
    ping.rcvTimeval.tv_sec = 3;  /* 3 Secs Timeout */
    ping.addrInfo = &ping.addrInfoStruct;
    ping.sizeof_pkt = (sizeof(ping.s_pkt)-sizeof(ping.s_pkt.msg)) + ping.msg_size;
    ping.pid = getpid();
}

void    halt(){ // print stats and exit.
    gettimeofday(&ping.GlobaltimeCount[1].Timeval, NULL);
    double time = (ping.GlobaltimeCount[1].Timeval.tv_usec - ping.GlobaltimeCount[0].Timeval.tv_usec)/1000.0+\
    (ping.GlobaltimeCount[1].Timeval.tv_sec - ping.GlobaltimeCount[0].Timeval.tv_sec)*1000.0;
    printf("\n--- %s ping statistics ---\n",ping.host_av_addr);
    printf("%d packets transmitted, %d packets received,",\
    ping.sent_count, ping.rcev_count);
    if (ping.errors)
        printf(" +%d errors,", ping.errors);
    printf(" %d%% packet loss, time %.0fms\n",\
    (int)(ping.sent_count - ping.rcev_count) / ping.sent_count * 100, time);
    if (ping.rcev_count){
        printf("round-trip min/avg/max = %.3f / %.3f / %.3f ms\n",\
        ping.rtt_stats[0],\
        ping.rtt_stats[2]/ping.rcev_count,\
        ping.rtt_stats[1]\
        );
    }
    freeaddrinfo(ping.addrInfo);
    exit(1);
}

void    statsSave(double time){
    if (ping.rtt_stats[0] > time) // min
        ping.rtt_stats[0] = time;
    if (ping.rtt_stats[1] < time) // max
        ping.rtt_stats[1] = time;
    ping.rtt_stats[2] += time; // total
}

void    prepare_s_pkt(){
    int i;
    ft_bzero(&ping.s_pkt, ping.sizeof_pkt);
    //// fillup icmp packet ////
    // set packet type to ICMP_ECHO
    ping.s_pkt.hdr.type = ICMP_ECHO;
    // set id to pid of process
    ping.s_pkt.hdr.un.echo.id = ping.pid;
    // fill msg (random)
    i = -1;
    if (ping.msg_size){
        while(++i < (int)ping.msg_size){
            ping.s_pkt.msg[i] = 'Z';
        }
        ping.s_pkt.msg[i] = '\0';
    }
    // fill sequance number
    ping.s_pkt.hdr.un.echo.sequence = ping.s_seq;
    // calculate checksum
    ping.s_pkt.hdr.checksum = checksum(&ping.s_pkt, ping.sizeof_pkt);
}

void    pingPong(){
    int loop;
    int rcv;

    NetIpHdr *r_ipHdr;
    uint8_t *r_ip; // uint32_t / 4, x.x.x.x

    prepare_s_pkt();
    // r message storage init
    char msgbuff[ping.sizeof_pkt+sizeof(NetIpHdr)];
    struct iovec iov[1];
    ft_bzero(&ping.r_msg, sizeof(ping.r_msg));
    
    // get send time
    gettimeofday(&ping.timeCount[0].Timeval, NULL);
    // send the packet
    ping.sent_count++;
    int snt = sendto(ping.sockfd, &ping.s_pkt, (size_t)ping.sizeof_pkt, 0, ping.addrInfo->ai_addr, sizeof(*ping.addrInfo->ai_addr));
    if (snt == -1){
        // ping.sent_count--;
        if (ping.verbose)
            printf("sendto : %s\n", strerror(errno));
        goto out;
    }
    if (ping.flood_flag)
        ft_putchar('.');
    ping.s_seq += (u_int16_t)1;

    // prepare to recieve
    ping.r_msg.msg_iov = iov;
    ping.r_msg.msg_iovlen = 1;
    ping.r_msg.msg_iov->iov_base = msgbuff;
    ping.r_msg.msg_iov->iov_len = sizeof(msgbuff);
    loop = 1;

    while (loop){ // to ignore all indesired icmp packets
        rcv = recvmsg(ping.sockfd, &ping.r_msg, 0);
        if (rcv == -1){
            if (ping.verbose)
                printf("recvmsg : %s\n", strerror(errno));
            else
                printf("recvmsg error, use -v for more information.\n");
            loop = 0;
        }
        else {
            r_ipHdr = (NetIpHdr *)msgbuff;
            ping.r_pkt = (struct ping_pkt *)&msgbuff[sizeof(NetIpHdr)];
            gettimeofday(&ping.timeCount[1].Timeval, NULL);
            double time = (ping.timeCount[1].Timeval.tv_usec - ping.timeCount[0].Timeval.tv_usec)/1000.0+(ping.timeCount[1].Timeval.tv_sec - ping.timeCount[0].Timeval.tv_sec)*1000.0;
            statsSave(time);
            if (ping.flood_flag){
                if (ping.r_pkt->hdr.type == ICMP_ECHOREPLY){
                    ping.rcev_count++;
                    loop = 0;
                    ft_putchar('\b');
                }
                goto end;   
            }
            r_ip = (uint8_t *)&r_ipHdr->src_addr;

            if (ping.r_pkt->hdr.type == ICMP_ECHOREPLY){
                if (ping.r_pkt->hdr.un.echo.id != ping.s_pkt.hdr.un.echo.id){
                    goto end;
                }
                printf("%d bytes from %d.%d.%d.%d: icmp_seq=%d ttl=%d time=%.3f ms\n",\
                rcv-(int)sizeof(NetIpHdr),\
                r_ip[0],r_ip[1],r_ip[2],r_ip[3],\
                ping.r_pkt->hdr.un.echo.sequence,\
                r_ipHdr->timetolive,\
                time\
                );
                ping.rcev_count++;
                loop = 0;
            }
            else if (ping.r_pkt->hdr.type == ICMP_UNREACH){
                r_ipHdr = (NetIpHdr *)((char*)msgbuff+sizeof(NetIpHdr)+8); 
                r_ip = (uint8_t *)&r_ipHdr->src_addr;
                if ((unsigned long)r_ipHdr->dest_addr != ((struct sockaddr_in *)ping.addrInfo->ai_addr)->sin_addr.s_addr){
                    goto end;
                }
                printf("from %d.%d.%d.%d: Destination unreachable\n",r_ip[0],r_ip[1],r_ip[2],r_ip[3]);
                loop = 0;
            }
            else if (ping.r_pkt->hdr.type == ICMP_TIMXCEED){// type 11 have 8 bytes then contain ip and icmp header
                r_ipHdr = (NetIpHdr *)((char*)msgbuff+sizeof(NetIpHdr)+8); 
                ping.r_pkt = (struct ping_pkt *)&msgbuff[(sizeof(NetIpHdr)*2+8)];
                if (ping.r_pkt->hdr.un.echo.id != ping.s_pkt.hdr.un.echo.id)
                    goto end;
                printf("from %d.%d.%d.%d icmp_seq=%d Time to Live exceeded\n",r_ip[0],r_ip[1],r_ip[2],r_ip[3], ping.r_pkt->hdr.un.echo.sequence);
                ping.errors++;
                loop = 0;
            }
        end:
        continue;
        }
    }
    out:
    ping.pong = 1;
}

void    usage(char *execName){
    printf("Usage:\n\t %s [options] <destination>\n", execName);
    printf("Options:\n");
    printf("\t-v                 verbose output\n");
    printf("\t-s <packetsize>    size of packet to send\n");
    printf("\t-c <count>         stop after <count> replies\n");
    printf("\t-t <ttl>           define time to live\n");
    printf("\t-W <timeout>       seconds to wait for a reply\n");
    printf("\t-i <interval>      interval between sending each packet\n");
    printf("\t-f                 flood ping\n");
    printf("\t-h                 display this help and exit\n");
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
            ping.verbose = 1;
        }
        else if (av[i][1] == 't' && ft_itsdigit(av[i+1])){
            ping.ttl = ft_atoi(av[i+1]);
            i++;
        }
        else if (av[i][1] == 'c' && ft_itsdigit(av[i+1])){
            ping.count_flag.enabler = 1;
            ping.count_flag.value = ft_atoll(av[i+1]) - 1;
            if (ping.count_flag.value < 0 || ping.count_flag.value > LLONG_MAX){
                printf("ping: invalid argument: '%lld': out of range: 1 <= value <= %lld\n",ping.count_flag.value + 1, LLONG_MAX);
                exit(1);
            }
            i++;
        }
        else if (av[i][1] == 's' && ft_itsdigit(av[i+1])){
            ping.msg_size = ft_atoi(av[i+1]);
            i++;
        }
        else if (av[i][1] == 'W' && ft_itsdigit(av[i+1])){
            ping.rcvTimeval.tv_sec = ft_atoi(av[i+1]);
            i++;
        }
        else if (av[i][1] == 'i' && ft_itsdigit(av[i+1])){
            ping.interval_flag = ft_atoi(av[i+1]);
            i++;
        }
        else if (av[i][1] == 'f'){
            ping.flood_flag = 1;
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
    ping.sizeof_pkt = sizeof(ping.s_pkt)-sizeof(ping.s_pkt.msg) + ping.msg_size;
    // get address info
    dns = getaddrinfo(av[i], NULL, NULL, &ping.addrInfo);
    if (dns != 0){
        printf("ping: %s: <destination> error : %s\n", av[i], gai_strerror(dns));
        exit(1);
    }
    else {
        // extract and print the ip address; networt to presentation
        inet_ntop(ping.addrInfo->ai_family, &((struct sockaddr_in *) ping.addrInfo->ai_addr)->sin_addr, ping.ipStr, INET_ADDRSTRLEN);
    }
    // open a raw socker with icmp prot
    ping.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ping.sockfd < 1)
    {
        printf("socket failed\n");
    }
    // set Time to live (ttl) to limit hops of the packert
    if (setsockopt(ping.sockfd, IPPROTO_IP, IP_TTL, &ping.ttl, sizeof(ping.ttl)) != 0){
        printf("setsockopt IP_TTL %s\n", strerror(errno));
    }
    // set socket receive timeout
    if (setsockopt(ping.sockfd, SOL_SOCKET, SO_RCVTIMEO, &ping.rcvTimeval, sizeof(ping.rcvTimeval)) != 0){
        printf("setsockopt SO_RCVTIMEO %s\n", strerror(errno));
    }
    ping.host_av_addr = av[i]; // save the host name memory address
    printf("PING %s (%s) %d(%d) bytes of data.\n", ping.host_av_addr, ping.ipStr, (int)ping.msg_size,(int)ping.sizeof_pkt);
    gettimeofday(&ping.GlobaltimeCount[0].Timeval, NULL);
    signal(SIGINT, halt); // ctrl+c signal
    if (ping.flood_flag)
        goto flood;
    pingPong();
    while (1){
        if (ping.pong){
            signal(SIGALRM,pingPong); // alarm signal to send ping
            alarm(ping.interval_flag);
            ping.pong = 0;
            if (ping.count_flag.enabler){
                if (ping.count_flag.value == 0){
                    halt();
                }
                ping.count_flag.value--;
            }
        }
    }
    flood:
    while (1)
        pingPong();
    return(0);
}
