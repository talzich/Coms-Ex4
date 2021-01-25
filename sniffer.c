
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h>

#define PACKET_LEN 512

int main()
{
    struct sockaddr saddr;
    struct packet_mreq mr_eq;
    char buffer[IP_MAXPACKET];
    int data, type, code, counter;
    counter = 0;

    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_fd < 0){
        perror("Unable to create socket");
        exit(1);
    }

    
    mr_eq.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr_eq,sizeof(mr_eq));


    printf("\n===== Sniffing for ICMP Packets =====\n\n");
    while (1)
    {       
        
        data = recvfrom(sock_fd, buffer, PACKET_LEN, 0, &saddr, (socklen_t *)sizeof(saddr));

        struct iphdr *ip_hdr = (struct iphdr *)(buffer + ETH_HLEN);
        if (ip_hdr->protocol == IPPROTO_ICMP)
        {
            struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + (4 * ip_hdr->ihl));

            type = (unsigned int)(icmp_hdr->type);
            code = (unsigned int)(icmp_hdr->code);

            // ICMP headers 8 and 0 are Echo and Echo reply respectively. 
            // Thus, those are teh packets we will be sniffing for.
            if (type == 0 || type == 8)
            {
                counter++;

                struct sockaddr_in source;
                bzero(&source, sizeof(source));
                source.sin_addr.s_addr = ip_hdr->saddr;

                struct sockaddr_in dest;
                bzero(&dest, sizeof(dest));
                dest.sin_addr.s_addr = ip_hdr->daddr;

                printf("=====Packet #%d Captured=====\n", counter);
                printf("Source Address: %s\n", inet_ntoa(source.sin_addr));
                printf("Destination Address: %s\n", inet_ntoa(dest.sin_addr));
                printf("ICMP Type: %d\n", type);
                printf("ICMP Code: %d\n", code);
                printf("===== End of Packet Data =====\n\n");
            }
        }
    }
    close(sock_fd);
    return 0;
}