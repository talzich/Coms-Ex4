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

#define PACKET_LEN 512

int main(void){

    struct sockaddr sock_addr;
    struct packet_mreq mr_eq;

    int counter, data; 
    char buffer[IP_MAXPACKET];

    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_fd < 0){
        perror("Error in creating socket");
        exit(1);
    }

    mr_eq.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr_eq,sizeof(mr_eq));

    counter = 0;

    printf("===== Sniffing for ICMP Packets =====");
    while(1){
        
        data = recvfrom(sock_fd, buffer, PACKET_LEN, 0, &sock_addr, (socklen_t *)sizeof(sock_addr));
        struct iphdr *ip_hdr = (struct iphdr *) buffer + ETH_HLEN;
        
        struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + (4 * ip_hdr->ihl));

            int hdr_type = (unsigned int)(icmp_hdr->type);
            int hdr_code = (unsigned int)(icmp_hdr->code);

            // ICMP headers of type 8 and 0 are or type Echo and Echo reply, respectfully.
            // Therefore, those are the packets we are interested in. 
            if (hdr_type == 0 || hdr_type == 8)
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
                printf("ICMP Details:\n");
                printf("ICMP Type: %d\n", hdr_type);
                printf("ICMP Code: %d\n", hdr_code);
                printf("===== End of Packet Data\n\n");
            }
        }
    }
    close(sock_fd);
    return 0;    
}