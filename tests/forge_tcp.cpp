/*!    forgetcp.c
 *     \Brief Generate TCP packets
 *     \Author jve
 *     \Date  sept. 2008
 *     \Source https://jve.linuxwall.info/ressources/code/forgetcp.c
 */

#include    <iostream>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>

/*!
  \def TCPHSIZE
 *
 * size of the tcp header, don't use options
 */
#define TCPHSIZE    20

/*!
  \def PSEUDOTCPHSIZE
 *
 * size of the pseudo tcp header use for the checksum computation
 */
#define PSEUDOTCPHSIZE    12

/*!
  \def IPHSIZE
 *
 * size of the ip header, don't use options
 */
#define IPHSIZE        20

/*!
  \def BUFSIZE
 *
 * number of bytes in the payload we want to copy to userspace
 * a regular ethernet connection limit payload size to 1500 bytes
 */
#define BUFSIZE 1500

/*!
 \def pseudo_tcp
 *
 \brief The pseudo header structure use to compute the tcp checksum
 *
 \param saddr, source ip address
 \param daddr, dest ip address
 \param mbz, flag (set to 0)
 \param ptcl, protocol number (6 for tcp)
 \param tcpl, tcp + payload length (at least 20)
 \param tcp, tcp header
 \param payload[BUFSIZE], payload buffer
 *
 */
struct pseudo_tcp
{
    unsigned saddr, daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;
    struct tcphdr tcp;
    char payload[BUFSIZE];
};

/*!
 \def packet
 *
 \brief The tcp packet structure
 *
 \param ip, ip header
 \param tcp, tcp header
 \param payload[BUFSIZE], payload buffer
 *
 */
struct packet
{
    struct iphdr ip;
    struct tcphdr tcp;
    char payload[BUFSIZE];
};

/*! in_cksum
 \brief Checksum routine for Internet Protocol family headers
 *
 \param[in] addr a pointer to the data
 \param[in] len the 32 bits data size
 *
 \return sum a 16 bits checksum
 */
unsigned short in_cksum(unsigned short *addr,int len)
{
    int sum = 0;
    u_short answer = 0;
    u_short *w = addr;
    int nleft = len;

        /*!
    * Our algorithm is simple, using a 32 bit accumulator (sum), we add
    * sequential 16 bit words to it, and at the end, fold back all the
    * carry bits from the top 16 bits into the lower 16 bits.
    */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /*! mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    /*! add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /*! add hi 16 to low 16 */
    sum += (sum >> 16);                     /*! add carry */
    answer = ~sum;                          /*! truncate to 16 bits */
    return(answer);
}






int main(int argc, char *argv[])
{
    if(argc < 3)
    {
        std::cout
            << "Forge TCP\n"
               "usage: gentcp <ip src> <ip dest> [<tcp fieds> <-P ascii payload>]\n\n"
               "IP:\t<ip src> & <ip dest> are mandatory\n\n"
               "TCP:\t-S = source port\n"
               "\t-D = dest port\n"
               "\t-Q = sequence number\n"
               "\t-A = ack number\n"
               "\t-u - urg flag\n"
               "\t-a - ack flag\n"
               "\t-p - psh flag\n"
               "\t-r - rst flag\n"
               "\t-s - syn flag\n"
               "\t-f - fin flag\n"
               "\t-w = window\n"
               "\t-c = checksum\n"
               "\t-P Payload = data to copy in TCP Payload field. MUST BE under " << std::min(1400, BUFSIZE) << " bytes\n\n"
               "example:\n"
               "\tsudo ./forgetcp 1.2.3.4 192.168.1.1 -S 5048 -D 443 -Q 12345 -A 0 -sa -w 15875\n\n"
               "\tsend a syn/ack packet from 1.2.3.4 to 192.168.1.1 on port 443\n"
               "\twith seq = 12345, ackseq = 0 and window = 15875\n\n";
        return 1;
    }



    int rawsocket  = 0;
    int one        = 1;
    struct sockaddr_in rawsin;
    int argslist;


    /*! create the packet with default values
     */
    struct packet p;
    memset(&p, 0x0, sizeof(struct packet));

    p.ip.version  = 4;
    p.ip.ihl      = IPHSIZE >> 2;
    p.ip.tos      = 0;
    p.ip.tot_len  = htons(IPHSIZE + TCPHSIZE);
    p.ip.id       = htons(rand()%65535);
    p.ip.frag_off = 0;
    p.ip.ttl      = htons(254);
    p.ip.protocol = IPPROTO_TCP;
    p.ip.saddr    = inet_addr(argv[1]);
    p.ip.daddr    = inet_addr(argv[2]);

    /*! create the tcp header (push ack packet)
     * size is always 20 bytes
     */
    p.tcp.source  = htons(atoi("54321"));
    p.tcp.dest    = htons(atoi("12345"));
    p.tcp.seq     = htonl(atoi("99999"));
    p.tcp.ack_seq = htonl(atoi("11111"));
    p.tcp.doff    = TCPHSIZE >> 2;
    p.tcp.urg     = 0;
    p.tcp.ack     = 0;
    p.tcp.psh     = 0;
    p.tcp.rst     = 0;
    p.tcp.syn     = 0;
    p.tcp.fin     = 0;
    p.tcp.window  = htons(atoi("16350"));
    p.tcp.check   = 0;    /*! set to 0 for later computing */
    p.tcp.urg_ptr = 0;

    /*! process arguments
     */
    size_t len;

    while(-1 != (argslist = getopt(argc, argv, "S:D:Q:A:uaprsfw:c:P:")))
    {
        switch (argslist)
        {
            case 'S' :
                p.tcp.source = htons(atoi(optarg));
                break;
            case 'D' :
                p.tcp.dest = htons(atoi(optarg));
                break;
            case 'Q' :
                p.tcp.seq = htonl(atol(optarg));
                break;
            case 'A' :
                p.tcp.ack_seq = htonl(atol(optarg));
                break;
            case 'u' :
                p.tcp.urg = 1;
                break;
            case 'a' :
                p.tcp.ack = 1;
                break;
            case 'p' :
                p.tcp.psh = 1;
                break;
            case 'r' :
                p.tcp.rst = 1;
                break;
            case 's' :
                p.tcp.syn = 1;
                break;
            case 'f' :
                p.tcp.fin = 1;
                break;
            case 'w' :
                p.tcp.window = htons(atoi(optarg));
                break;
            case 'c' :
                p.tcp.check = atoi(optarg);
                break;

            case 'P' :
                len = strlen(optarg);
                if(len > sizeof(p.payload))
                {
                    std::cerr
                        << "payload is limited to "
                        << BUFSIZE
                        << " characters.\n";
                    return 1;
                }
                std::cout
                    << "loading " << len
                    << " bytes payload: " << optarg
                    << "\n";
                strncpy(p.payload, optarg, len);
                break;
        }
    }

    /*! update ip total length
     */
    p.ip.tot_len = htons(strlen(p.payload) + IPHSIZE + TCPHSIZE);

    /*! compute the ip checksum
     */
    p.ip.check = (unsigned short)in_cksum((unsigned short *)&p.ip, IPHSIZE);

    /*! if tcp checksum has not been forced, compute it
     */
    if(p.tcp.check == 0)
    {

        /*! pseudo tcp header for the checksum computation
         */
        struct pseudo_tcp p_tcp;
        memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

        p_tcp.saddr     = p.ip.saddr;
        p_tcp.daddr     = p.ip.daddr;
        p_tcp.mbz     = 0;
        p_tcp.ptcl     = IPPROTO_TCP;
        p_tcp.tcpl     = htons(TCPHSIZE + strlen(p.payload));
        memcpy(&p_tcp.tcp, &p.tcp, TCPHSIZE + strlen(p.payload));

        /*! compute the tcp checksum
         *
         * TCPHSIZE is the size of the tcp header
         * PSEUDOTCPHSIZE is the size of the pseudo tcp header
         */
        p.tcp.check = (unsigned short)in_cksum((unsigned short *)&p_tcp, strlen(p.payload) + TCPHSIZE + PSEUDOTCPHSIZE);
    }


    /* init the raw socket 
     */
    rawsocket = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(setsockopt(rawsocket,IPPROTO_IP,IP_HDRINCL,(char *)&one,sizeof(one)) < 0)
    {
        fprintf(stderr,"\nError creating raw socket.....\n");
        return -1;
    }
    
    rawsin.sin_family    = AF_INET;
    rawsin.sin_port        = p.tcp.dest;
    rawsin.sin_addr.s_addr    = p.ip.daddr;

    /*! send the packet
     */
    int bytes_sent = sendto(rawsocket,
                &p,
                ntohs(p.ip.tot_len),
                0,
                (struct sockaddr *) &rawsin,
                sizeof (rawsin)
                );

    fprintf(stdout,"%d bytes sent\n",bytes_sent);

    return 0;
}

// vim: ts=4 sw=4 et
