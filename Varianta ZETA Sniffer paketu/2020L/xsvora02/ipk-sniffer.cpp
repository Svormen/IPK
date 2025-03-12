#include <stdio.h>  
#include <string.h>    
#include <stdlib.h>  
#include <unistd.h> 
#include <ctype.h>
#include <stdbool.h>  
#include <sys/time.h>  
#include <time.h>      
#include <signal.h>
#include <arpa/inet.h>    
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <getopt.h>
#include <net/ethernet.h>
#include <pcap.h>

// Session handle
pcap_t *handle;

// types of arguments
#define no_argument 0
#define required_argument 1 
#define optional_argument 2

// types IPv4 and IPv6
#define set_IPv4 2048
#define set_IPv6 34525

// Print all interfaces
void find_interfaces() {
    char error_inter[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces,*temp;
    int i=0;
    if(pcap_findalldevs(&interfaces,error_inter)==-1)
    {
        printf("error in pcap findall devs\n");
        exit(EXIT_FAILURE);
    }

    printf("The interfaces present on the system are:\n");
    for(temp=interfaces;temp;temp=temp->next)
    {
        printf("%d : %s\n",i++,temp->name); 
    }
}

void run_cup(pcap_t *handle, int par_n_number, pcap_handler funct) {
    // start capturing packet_number
    //printf("TU\n");
    //printf("number:%d\n", par_n_number);
    if (pcap_loop(handle, par_n_number, funct, 0) < 0) {
        printf("ERROR: problem with pcap_loop wrong: %s\n", pcap_geterr(handle));
    }
}

void print_all(
    const unsigned char *print_packet,
    int amount,
    int hdr_amount
) {
    bool hdr_put = false;
    
    // we have 1 line 0x0000:
    int num_lines = 1;
    printf("0x0000:  ");

    int hdr_wanted = hdr_amount % 16;
    for (int i = 0; i < amount; i++) {
        if (hdr_put ? (i != hdr_amount && (i - hdr_wanted) % 16 == 0) : (i % 16 == 0 && i != 0)) {
            printf(" ");
            for (int j = i - 16; j < i; j++) {
                // check with function isprint if it is allowed character
                if (isprint(print_packet[j])) {
                    printf("%c", (unsigned char) print_packet[j]);
                } else {
                    // not allowed character then print '.'
                    printf(".");
                }
                // we need space between bytes
                if (j == i - 9) {
                    printf(" ");
                }
            }
            // need print new line
            printf("\n");

            // check number of bytes
            if (num_lines < 10) {
                printf("0x00%d:  ", num_lines * 10);
                num_lines++;
            } else if (num_lines < 100) {
                printf("0x0%d:  ", num_lines * 10);
                num_lines++;
            } else {
                printf("0x%d:  ", num_lines * 10);
                num_lines++;
            }
        }

        /*if ((((hdr_put ? i - hdr_wanted : i) - 8) % 16) == 0) {
            printf(" ");
        }*/
        // we need space after 8 bytes
        if (hdr_put == true) {
            if (((i - hdr_wanted - 8) % 16) == 0) {
                printf(" ");
            }
        } else {
            if (((i - 8) % 16) == 0) {
                printf(" ");
            }
        }

        // hex print
        printf("%02X ", (unsigned char) print_packet[i]);

        // last line
        if ((hdr_amount - 1 == i) || (i == amount - 1)) {
            // print spaces
            for (int j = 0; j < 15 - ((hdr_put ? i - hdr_wanted : i) % 16); j++) {
                printf("   ");
                // spaces between bytes
                if (j == 7) {
                    printf(" ");
                }
            }
            
            // change boolean value
            if (hdr_amount != amount) {
                if (hdr_put == true) {
                    hdr_put = false;
                } else {
                    hdr_put = true;
                }
            }
            
            // space between bytes and data
            printf(" ");

            // print all remaining data
            for (int j = (!hdr_put ? (hdr_amount == amount) ? (i - (i % 16)) : (i - ((i - hdr_wanted) % 16)) : hdr_amount - hdr_wanted); j <= (!hdr_put ? i : hdr_amount - 1); j++) {
                if (!isprint(print_packet[j])) {
                    printf(".");
                } else {
                    printf("%c", (unsigned char) print_packet[j]);
                }

                if (hdr_put == false) {
                    if (hdr_amount == amount) {
                        if (j == i - (i % 16) + 7) {
                            printf(" ");
                        }
                    } else {
                        if (j == i - ((i - hdr_wanted) % 16) + 7) {
                            printf(" ");
                        }
                    }
                } else {
                    if (j == hdr_amount - (hdr_amount % 16) + 7) {
                        printf(" ");
                    }
                }
            }

            // // check number of bytes
            if (hdr_amount != amount && hdr_put) {
                printf("\n\n");
                if (num_lines < 10) {
                    printf("0x00%d:  ", num_lines * 10);
                    num_lines++;
                } else if (num_lines < 100) {
                    printf("0x0%d:  ", num_lines * 10);
                    num_lines++;
                } else {
                    printf("0x%d:  ", num_lines * 10);
                    num_lines++;
                }
            } else {
                // print space
                printf("\n");
            }

        }
    }
}

void packet_check(
    u_char *args,
    const struct pcap_pkthdr* header,
    const u_char* packet
) {
    bool ipv4_in = false;
    bool ipv6_in = false;

    // get Time with mil. sec and time zone   
    struct timeval tv;
    struct timeval tv_mil;
    time_t t;
    struct tm *info;
    char buffer[64];
    gettimeofday(&tv, NULL);
    gettimeofday(&tv_mil, NULL);
    // get time in sec
    t = tv.tv_sec;
    info = localtime(&t);
    strftime (buffer, sizeof buffer, "%FT%T", info);
    printf("%s",buffer);
    // get mil. sec
    t = tv_mil.tv_usec/1000;
    printf(".%03ld", t);
    strftime (buffer, sizeof buffer, "%z", info);
    printf("%.3s:00 ", buffer);

    // struct ether_header
    struct ether_header *eth_header;
    
    // sizeof(struct ether_header) is 14
    eth_header = (struct ether_header *) packet;

    // bool variable for checking if it is IP
    bool check_ip = false;
    
    // check type if IP or ARP
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        check_ip = true;
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    }

    // if it is IP
    if (check_ip == true) {
        // prepare for checking if it is ipv4 or ipv6
        int whitch_ip = ((int) (packet[12]) << 8) | (int) packet[13];
        switch(whitch_ip)
        {
            case set_IPv4:
                ipv4_in = true;
                break;
            case set_IPv6:
                ipv6_in = true;
                break;
            default:
                return;
        }

        // arrayss for ip add
        char src_ip[256];
        char dest_ip[256];
        struct ip *hdr_ip4;
        struct ip6_hdr* hdr_ip6;
        
        int hdr_len = 14;
        // ignore datalink layer
        const u_char* tptr = packet + hdr_len;

        // get IPv4
        if (ipv4_in == true) {
            hdr_ip4 = (struct ip *) tptr;
            strcpy(src_ip, inet_ntoa(hdr_ip4->ip_src));
            strcpy(dest_ip, inet_ntoa(hdr_ip4->ip_dst));
            // header transport layer
            tptr += 4 * hdr_ip4->ip_hl;
        }
        
        int hdr_plus = -1;

        // get IPv6
        if (ipv6_in == true) {
            hdr_ip6 = (struct ip6_hdr*) tptr;

            inet_ntop(AF_INET6, &(hdr_ip6->ip6_src), src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(hdr_ip6->ip6_dst), dest_ip, INET6_ADDRSTRLEN);

            tptr = tptr + 40;
        }

        // structs for tcp and udp header
        struct tcphdr* hdr_tcp;
        struct udphdr* hdr_udp;

        switch(ipv6_in ? hdr_ip6->ip6_nxt : hdr_ip4->ip_p)
        {
            case IPPROTO_TCP:
                hdr_tcp = (struct tcphdr*) tptr;
                printf("%s : %d > %s : %d, length %d bytes\n\n", src_ip, ntohs(hdr_tcp->source), dest_ip, ntohs(hdr_tcp->dest), header->caplen);
                if (ipv6_in == true) {
                    print_all(packet, header->caplen, hdr_len + 40 + 4 * hdr_tcp->doff);
                }
                if (ipv4_in == true) {
                    print_all(packet, header->caplen, hdr_len + 4 * hdr_ip4->ip_hl + 4 * hdr_tcp->doff);
                }
                printf("\n\n");
                break;

            case IPPROTO_UDP:
                hdr_udp = (struct udphdr*) tptr;
                printf("%s : %d > %s : %d, length %d bytes\n\n", src_ip, ntohs(hdr_udp->source), dest_ip, ntohs(hdr_udp->dest), header->caplen);
                if (ipv6_in == true) {
                    print_all(packet, header->caplen, hdr_len + 40 + 8);
                }
                if (ipv4_in == true) {
                    print_all(packet, header->caplen, hdr_len + 4 * hdr_ip4->ip_hl + 8);
                }
                printf("\n\n");
                break;
        }
    }
}


pcap_t *pcap_open(char *dev, const char *filter_type) {
    // Error string
    char errbuf[PCAP_ERRBUF_SIZE];
    // The compiled filter expression
    struct bpf_program bpfs;
    // The netmask of our sniffing device
    bpf_u_int32 mask;
    // The IP of our sniffing device	
	bpf_u_int32 net;
    // The header that pcap gives us
    struct pcap_pkthdr header;
    //The actual packet
	const u_char *packet;

    // if pcap_lookupdev() fails, it will store an error message in errbuf
    if (!*dev) {
        dev = pcap_lookupdev(errbuf);
        printf("device: %s\n", dev);
        if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(NULL);
        }
	}

    // open the device, tells it to read
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(NULL);
    }

    // get device netmask and ip address
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
        return NULL;
	}

    // get packet from converting filter_type
    if (pcap_compile(handle, &bpfs, filter_type, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_type, pcap_geterr(handle));
		return(NULL);
	}

    // assign packet to libpcap socket
	if (pcap_setfilter(handle, &bpfs) == -1) {
	    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_type, pcap_geterr(handle));
		return(NULL);
	}

    return handle;
}


int main (int argc, char *argv[])
{
    // process long arguments
    const struct option longopts[] = 
    {
        {"interface", required_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, '1'},
        {"icmp", no_argument, 0, '2'},
        {0,0,0,0},
    };

    char intr[256] = "";
    char port_num[20] = "port ";
    char filter_type[256] = "";
    int index;
    int iarg=0;
    int par_n_number = 1;
    bool icmp_in = false;
    bool arp_in = false;
    // bool variables for tcp and udp
    bool tcp_in = false;
    bool udp_in = false;
    // bool variable for interface
    bool inter_in = false;
    bool inter_in2 = false;
    // turn off getopt error message
    opterr=1; 

    while (iarg != -1)
    {
        // set options of arguments
        iarg = getopt_long(argc, argv, ":i:p:tun:", longopts, &index);
        // switch for all argument combination
        switch(iarg)
        {
            case 'i':
                inter_in = true;
                strcpy(intr, optarg);
                break;
            case 'p':
                // concat port with optarg
                strcat(port_num, optarg);
                strcat(port_num, " and");
                break;
            case 'n':
                // get int number thanks atoi
                par_n_number = atoi(optarg);
                break;
            case 't':
                tcp_in = true;
                break;
            case 'u':
                udp_in = true;
                break;
            case '1':
                arp_in = true;
                break;
            case '2':
                icmp_in = true;
                break;
            // optional arguments
            case ':':
                if (optopt == 'i')
                {
                    inter_in2 = true;
                }
                break;
            // unavailable arguments
            case '?':
                fprintf (stderr, "ERROR: Wrong arguments\n");
                return 1;
        }
    }

    // check if there is port and concat 
    if (strcmp(port_num, "port ") != 0) {
        strcat(filter_type, port_num);
    }
    // call function for getting all interfaces only ./ipk-sniffer -i
    if (inter_in2 && argc == 2) {
        find_interfaces();
        return 0;
    }
    if (argc == 1){
        find_interfaces();
        return 0;
    }
    if ((tcp_in == true) && (udp_in == true)) {
        strcat(filter_type, " (tcp or udp)");
    } else {
        // tcp in arguemnt
        if (tcp_in) {
            strcat(filter_type, " (tcp)");
        }
        // udp in arguemnt
        if (udp_in) {
            strcat(filter_type, " (udp)");
        }
    }
    
    // icmp in arguemnt
    if (icmp_in) {
        strcat(filter_type, " icmp");
    }
    // arp in arguemnt
    if (arp_in) {
        strcat(filter_type, " arp");
    }
    
    
    if (handle = pcap_open(intr, filter_type)) {
        run_cup(handle, par_n_number, (pcap_handler) packet_check);
        pcap_close(handle);
    }
    
    // everything is OK
    return 0;
}
