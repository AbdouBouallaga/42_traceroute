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
// 

void init_ping(){ // init ping struct
    ft_bzero(&tR.addrInfo, sizeof(struct addrinfo));
    tR.pong = 1;
    tR.verbose = 0;
    tR.msg_size = 56;
    tR.interval_flag = 1;
    tR.flood_flag = 0;
    tR.count_flag.enabler = 0; //flag -c enabler
    tR.count_flag.value = 0; //flag -c value
    tR.sent_count = 0;
    tR.rcev_count = 0;
    tR.ttl = 1;
    ///
    tR.max_hops = 64;
    tR.last_addr = 0;
    tR.hop = 1;
    tR.last_hop = 0;
    ///
    tR.rtt_stats[0] = INT16_MAX; // min
    tR.rtt_stats[1] = 0; // max
    tR.rtt_stats[2] = 0; // total
    tR.rcvTimeval.tv_sec = 3;  /* 3 Secs Timeout */
    tR.addrInfo = &tR.addrInfoStruct;
    tR.sizeof_pkt = (sizeof(tR.s_pkt)-sizeof(tR.s_pkt.msg)) + tR.msg_size;
    tR.pid = getpid();
}

void    halt(){ // print stats and exit.
    // gettimeofday(&tR.GlobaltimeCount[1].Timeval, NULL);
    // double time = (tR.GlobaltimeCount[1].Timeval.tv_usec - tR.GlobaltimeCount[0].Timeval.tv_usec)/1000.0+\
    // (tR.GlobaltimeCount[1].Timeval.tv_sec - tR.GlobaltimeCount[0].Timeval.tv_sec)*1000.0;
    // printf("\n--- %s ping statistics ---\n",tR.host_av_addr);
    // printf("%d packets transmitted, %d packets received,",\
    // tR.sent_count, tR.rcev_count);
    // if (tR.errors)
    //     printf(" +%d errors,", tR.errors);
    // printf(" %d%% packet loss, time %.0fms\n",\
    // (int)(tR.sent_count - tR.rcev_count) / tR.sent_count * 100, time);
    // if (tR.rcev_count){
    //     printf("round-trip min/avg/max = %.3f / %.3f / %.3f ms\n",\
    //     tR.rtt_stats[0],\
    //     tR.rtt_stats[2]/tR.rcev_count,\
    //     tR.rtt_stats[1]\
    //     );
    // }
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

void    prepare_s_pkt(){
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
            tR.errors--;
        }
    }
}

void    pingPong(){
    int loop;
    int rcv;
    int wind = 0;

    // NetIpHdr *r_ipHdr;
    // uint8_t *r_ip; // uint32_t / 4, x.x.x.x

    prepare_s_pkt();
    char msg[92];
    ft_bzero(&tR.r_msg, sizeof(tR.r_msg));
    
    // get send time
    gettimeofday(&tR.timeCount[0].Timeval, NULL);
    // send the packet
    tR.sent_count++;
    int snt = sendto(tR.sockfd, &tR.s_pkt, (size_t)tR.sizeof_pkt, 0, tR.addrInfo->ai_addr, sizeof(*tR.addrInfo->ai_addr));
    if (snt == -1){
        printf("sendto : %s\n", strerror(errno));
        goto out;
    }

    tR.s_seq += (u_int16_t)1;

    loop = 1;

    while (loop){ // to ignore all indesired icmp packets
        rcv = recvfrom(tR.sockfd, &msg, sizeof(msg), 0, NULL, NULL);
        if (rcv == -1){
            tR.errors++;
            if (tR.errors > 2){
                printf("\t*\t*\t*");
                tR.errors = 0;
            }
            loop = 0;
        }
        else {
            tR.r_ipHdr = (NetIpHdr *)msg;
            tR.r_pkt = (struct ping_pkt *)&msg[sizeof(NetIpHdr)];
            // tR.r_ip = (uint8_t *)&tR.r_ipHdr->src_addr;
            // printf("type %d\n", tR.r_pkt->hdr.type);
            gettimeofday(&tR.timeCount[1].Timeval, NULL);
            double time = (tR.timeCount[1].Timeval.tv_usec - tR.timeCount[0].Timeval.tv_usec)/1000.0+(tR.timeCount[1].Timeval.tv_sec - tR.timeCount[0].Timeval.tv_sec)*1000.0;
            statsSave(time);
            if (tR.r_pkt->hdr.type == ICMP_ECHOREPLY){
                if(tR.max_hops > 3)
                    tR.max_hops = 3;
                if (tR.r_pkt->hdr.un.echo.id != tR.s_pkt.hdr.un.echo.id){
                    goto end;
                }
                // if (tR.last_addr != tR.r_ipHdr->src_addr){
                //     tR.last_addr = tR.r_ipHdr->src_addr;
                //     // ft_bzero(&tR.fqdn, sizeof(tR.fqdn));
                //     // inet_pton(AF_INET, (const char *)r_ip, &tR.last_addr);
                //     // getnameinfo((struct sockaddr*)tR.addrInfo->ai_addr,sizeof(tR.addrInfo->ai_addr),tR.fqdn,sizeof(tR.fqdn),0,0,0);
                //     printf("\t %d %s(%d.%d.%d.%d)", tR.rcev_count, tR.fqdn, r_ip[0], r_ip[1], r_ip[2], r_ip[3]);
                // }
                // printf("\t %.3fms", time);
                // loop = 0;
                trace_write();
                printf("  %.3fms", time);
                loop = 0;
                // printf("from %d.%d.%d.%d icmp_seq=%d Time to Live exceeded\n",r_ip[0],r_ip[1],r_ip[2],r_ip[3], tR.r_pkt->hdr.un.echo.sequence);
                loop = 0;
                tR.max_hops--;
            }
            else if (tR.r_pkt->hdr.type == ICMP_TIMXCEED){// type 11 have 8 bytes then contain ip and icmp header
                tR.r_pkt = (struct ping_pkt *)&msg[(sizeof(NetIpHdr)*2+8)];
                if (tR.r_pkt->hdr.un.echo.id != tR.s_pkt.hdr.un.echo.id)
                    goto end;
                trace_write();
                printf("  %.3fms", time);
                loop = 0;
            }
            else {
                tR.r_pkt = (struct ping_pkt *)&msg[(sizeof(NetIpHdr)*2+8)];
                if (tR.r_pkt->hdr.un.echo.id != tR.s_pkt.hdr.un.echo.id)
                    goto end;
                trace_write();
                printf("\t*");
                loop = 0;
            }
        end:
        continue;
        }
    }
    out:
    tR.pong = 1;
}

void    usage(char *execName){
    printf("Usage:\n\t %s [options] <destination>\n", execName);
    printf("Options:\n");
    printf("\t-v                 verbose output\n");
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
        else if (av[i][1] == 't' && ft_itsdigit(av[i+1])){
            tR.ttl = ft_atoi(av[i+1]);
            i++;
        }
        else if (av[i][1] == 'c' && ft_itsdigit(av[i+1])){
            tR.count_flag.enabler = 1;
            tR.count_flag.value = ft_atoll(av[i+1]) - 1;
            if (tR.count_flag.value < 0 || tR.count_flag.value > LLONG_MAX){
                printf("ping: invalid argument: '%lld': out of range: 1 <= value <= %lld\n",tR.count_flag.value + 1, LLONG_MAX);
                exit(1);
            }
            i++;
        }
        else if (av[i][1] == 's' && ft_itsdigit(av[i+1])){
            tR.msg_size = ft_atoi(av[i+1]);
            i++;
        }
        else if (av[i][1] == 'W' && ft_itsdigit(av[i+1])){
            tR.rcvTimeval.tv_sec = ft_atoi(av[i+1]);
            i++;
        }
        else if (av[i][1] == 'i' && ft_itsdigit(av[i+1])){
            tR.interval_flag = ft_atoi(av[i+1]);
            i++;
        }
        else if (av[i][1] == 'f'){
            tR.flood_flag = 1;
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
    // hints init
    ft_bzero(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;
    // hints.ai_flags = AI_DEFAULT;
    // dns check
    dns = getaddrinfo(av[i], NULL, &hints, &tR.addrInfo);
    if (dns != 0){
        printf("%s: %s , <destination> error : %s\n", av[0], av[i], gai_strerror(dns));
        exit(1);
    }
    // printf("tR.addrInfo->ai_canonname = %s\n", tR.addrInfo->ai_canonname);
    // printf("tR.addrInfo->ai_addr->sa_data = %s\n", tR.addrInfo->ai_addr->sa_data);
    // printf("tR.addrInfo->ai_addr->sa_family = %d\n", tR.addrInfo->ai_addr->sa_family);
    // printf("tR.addrInfo->ai_addr->sa_len = %d\n", tR.addrInfo->ai_addr->sa_len);
    // printf("tR.addrInfo->ai_addrlen = %d\n", tR.addrInfo->ai_addrlen);
    // printf("tR.addrInfo->ai_canonname = %s\n", tR.addrInfo->ai_canonname);
    // printf("tR.addrInfo->ai_family = %d\n", tR.addrInfo->ai_family);
    // printf("tR.addrInfo->ai_flags = %d\n", tR.addrInfo->ai_flags);
    // printf("tR.addrInfo->ai_next = %p\n", tR.addrInfo->ai_next);
    // printf("tR.addrInfo->ai_protocol = %d\n", tR.addrInfo->ai_protocol);
    // printf("tR.addrInfo->ai_socktype = %d\n", tR.addrInfo->ai_socktype);
    // extract and print the ip address; networt to presentation
    inet_ntop(tR.addrInfo->ai_family, &((struct sockaddr_in *) tR.addrInfo->ai_addr)->sin_addr, tR.ipStr, INET_ADDRSTRLEN);
    // int err=getnameinfo((struct sockaddr*)tR.addrInfo->ai_addr,sizeof(tR.addrInfo->ai_addr),tR.fqdn,sizeof(tR.fqdn),0,0,0);
    // if (err!=0) {
    //     printf("Failed to get FQDN. error: %s",strerror(err));
    //     exit(1);
    // }
    // open a raw socker with icmp prot
    tR.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (tR.sockfd < 1)
    {
        printf("socket failed\n");
    }
    // set Time to live (ttl) to limit hops of the packert
    if (setsockopt(tR.sockfd, IPPROTO_IP, IP_TTL, &tR.ttl, sizeof(tR.ttl)) != 0){
        printf("setsockopt IP_TTL %s\n", strerror(errno));
    }
    // set socket receive timeout
    if (setsockopt(tR.sockfd, SOL_SOCKET, SO_RCVTIMEO, &tR.rcvTimeval, sizeof(tR.rcvTimeval)) != 0){
        printf("setsockopt SO_RCVTIMEO %s\n", strerror(errno));
    }
    tR.host_av_addr = av[i]; // save the host name memory address
    printf("traceroute to %s (%s), %d hops max, %d byte packets\n", tR.host_av_addr, tR.ipStr, tR.max_hops, tR.sizeof_pkt);
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
                if (setsockopt(tR.sockfd, IPPROTO_IP, IP_TTL, &tR.ttl, sizeof(tR.ttl)) != 0){
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
