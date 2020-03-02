#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <map>
#include <list>
#include <set>

using namespace std;


//Ethernet header structure.
struct Ethernet_header{
    char D_mac[6];
    char S_mac[6];
    u_int16_t Type;
}; //14-Bytes.

//IPv4 header structure.
struct IPv4_header{
    uint8_t version;
    uint8_t protocol;
    uint32_t S_ip;
    uint32_t D_ip;
    uint16_t len;
}; //len-Bytes.

//TCP header structure.
struct TCP_header{
    uint16_t S_port;
    uint16_t D_port;
    uint8_t Data_offset;
}; //Data_offset-Bytes.

void usage() // inform user about usage of this application.
{
  printf("syntax: pcap_stat <pcap file_name>\n");
  printf("sample: pcap_stat pcap_sample.pcapng \n");
}

struct Ethernet_header *set_Ether(const u_char *p) //setup Ethernet header with packet data.
{
    int i = 0;
    struct Ethernet_header *EH = reinterpret_cast<struct Ethernet_header*>(malloc(sizeof(struct Ethernet_header)));
    u_int8_t type[2] = {p[12],p[13]};
    uint16_t *type_in_header = reinterpret_cast<uint16_t *>(type);
    for(i = 0; i < 6; i++)
        EH->D_mac[i] = p[i];
    for(i = 0; i < 6; i++)
        EH->S_mac[i] = p[i + 6];

    EH->Type = ntohs(*type_in_header);
    return EH;
}//Done.

struct IPv4_header *set_ip(const u_char *p) //setup IP header with packet data.
{
    struct IPv4_header *IH = reinterpret_cast<struct IPv4_header*>(malloc(sizeof(struct IPv4_header)));
    uint8_t sip[] = {p[26], p[27], p[28], p[29]};
    uint8_t dip[] = {p[30], p[31], p[32], p[33]};
    uint32_t *sipp = reinterpret_cast<uint32_t *>(sip);
    uint32_t *dipp = reinterpret_cast<uint32_t *>(dip);
    IH->len = p[14] & 0x0f;
    IH->version = p[14] >> 4;
    IH->protocol = p[23];
    IH->S_ip = ntohl(*sipp);
    IH->D_ip = ntohl(*dipp);
    return IH;
}

class MAC
{
public:
    char Mac_add[6];

    MAC(char* mac_add)
    {
        Mac_add[0] = mac_add[0];
        Mac_add[1] = mac_add[1];
        Mac_add[2] = mac_add[2];
        Mac_add[3] = mac_add[3];
        Mac_add[4] = mac_add[4];
        Mac_add[5] = mac_add[5];
    }

    bool operator<(const MAC& target) const
    {
        for(int i = 0; i < 5; i++)
        {
            if(Mac_add[i] != target.Mac_add[i])
                return Mac_add[i] < target.Mac_add[i];
        }
        return Mac_add[5] < target.Mac_add[5];
    }

};
class Conv_MAC
{
public:
    char smac[6];
    char dmac[6];
    Conv_MAC(char* smac, char* dmac)
    {
        this->dmac[0] = dmac[0];
        this->dmac[1] = dmac[1];
        this->dmac[2] = dmac[2];
        this->dmac[3] = dmac[3];
        this->dmac[4] = dmac[4];
        this->dmac[5] = dmac[5];
        this->smac[0] = smac[0];
        this->smac[1] = smac[1];
        this->smac[2] = smac[2];
        this->smac[3] = smac[3];
        this->smac[4] = smac[4];
        this->smac[5] = smac[5];

    }

    bool operator<(const Conv_MAC& target) const
    {
        for(int i = 0; i < 6; i++)
        {
            if(smac[i] != target.smac[i])
                return smac[i] < target.smac[i];
        }
        for(int i = 0; i < 5; i++)
        {
            if(dmac[i] != target.dmac[i])
                return dmac[i] < target.dmac[i];
        }
        return dmac[5] < target.dmac[5];
    }

};

class Conv_IP
{
public:
    uint32_t sip;
    uint32_t dip;
    Conv_IP(uint32_t sip, uint32_t dip)
    {
        this->sip = sip;
        this->dip = dip;
    }
    bool operator<(const Conv_IP& target) const
    {
        if(sip != target.sip)
        {
            return sip < target.sip;
        }

            return dip < target.dip;
    }
};

class Container
{
public:
    int recv_count;
    int recv_bytes;
    int send_count;
    int send_bytes;

    Container(int recv_count, int recv_bytes, int send_count, int send_bytes)
    {
        this->recv_count = recv_count;
        this->recv_bytes = recv_bytes;
        this->send_count = send_count;
        this->send_bytes = send_bytes;
    }

    void plus_recv_count(int a)
    {
        this->recv_count += a;
    }

    void plus_send_count(int a)
    {
        this->send_count += a;
    }
    void plus_recv_bytes(int a)
    {
        this->recv_bytes += a;
    }
    void plus_send_bytes(int a)
    {
        this->send_bytes += a;
    }
};

int main(int argc, char* argv[]) {
  //if (argc != 2) {
  //  usage();
  //  return -1;
  //}

  char file_name[] = "../pcap_stat/pcap_sample.pcapng";
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_offline(file_name, errbuf);
  if (!handle)
  {
      fprintf(stderr, "could not read file %s : %s\n", file_name, errbuf);
      return -1;
  }

  map<uint32_t, int> ep_ip_receive_count;
  map<uint32_t, int> ep_ip_receive_byte;
  map<uint32_t, int> ep_ip_send_count;
  map<uint32_t, int> ep_ip_send_byte;
  map<MAC, int> ep_mac_receive_count;
  map<MAC, int> ep_mac_receive_byte;
  map<MAC, int> ep_mac_send_count;
  map<MAC, int> ep_mac_send_byte;
  map<Conv_MAC, int> conv_mac_count;
  map<Conv_MAC, int> conv_mac_byte;
  map<Conv_IP, int> conv_ip_count;
  map<Conv_IP, int> conv_ip_byte;


  map<uint32_t, Container*> ip_container;
  map<MAC, Container*> mac_container;
  map<Conv_IP, Container*> conv_ip_container;
  map<Conv_MAC, Container*> conv_mac_container;

  while(true)
  {
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(handle, &header, &packet);
      if (res == 0) continue;
      if (res == -1 || res == -2) break;


      struct Ethernet_header *Ether = set_Ether(packet);
      struct IPv4_header *IP = set_ip(packet);

      if(Ether->Type != 0x0800)
      {
          free(IP);
          free(Ether);
          continue;
      }
      Conv_MAC conv_mac = Conv_MAC(Ether->S_mac, Ether->D_mac);
      Conv_IP conv_ip = Conv_IP(IP->S_ip, IP->D_ip);

      if(ep_ip_receive_count.find(IP->D_ip) != ep_ip_receive_count.end())
      {
          ep_ip_receive_count[IP->D_ip]++;
          ep_ip_receive_byte[IP->D_ip] += header->caplen;
      }
      else
      {
          ep_ip_receive_count.insert(make_pair(IP->D_ip, 1));
          ep_ip_receive_byte.insert(make_pair(IP->D_ip, header->caplen));
      }
      if(ep_ip_send_count.find(IP->S_ip) != ep_ip_send_count.end())
      {
          ep_ip_send_count[IP->S_ip]++;
          ep_ip_receive_byte[IP->S_ip] += header->caplen;
      }
      else
      {
       ep_ip_send_count.insert(make_pair(IP->S_ip, 1));
       ep_ip_send_byte.insert(make_pair(IP->S_ip, header->caplen));
      }
      if(ep_mac_receive_count.find(MAC(Ether->D_mac)) != ep_mac_receive_count.end())
      {
          ep_mac_receive_count.at(Ether->D_mac) += 1;
          ep_mac_receive_byte[MAC(Ether->D_mac)] += header->caplen;
      }
      else
      {
       ep_mac_receive_count.insert(make_pair(Ether->D_mac, 1));
       ep_mac_receive_byte.insert(make_pair(Ether->D_mac, header->caplen));
      }
      if(ep_mac_send_count.find(MAC(Ether->S_mac)) != ep_mac_send_count.end())
      {
          ep_mac_send_count[MAC(Ether->S_mac)] += 1;
          ep_mac_send_byte[MAC(Ether->S_mac)] += header->caplen;
      }
      else
      {
       ep_mac_send_count.insert(make_pair(Ether->S_mac, 1));
       ep_mac_send_byte.insert(make_pair(Ether->S_mac, header->caplen));
      }
      if(conv_ip_count.find(conv_ip) != conv_ip_count.end())
      {
          conv_ip_count[conv_ip] += 1;
          conv_ip_byte[conv_ip] += header->caplen;
      }
      else
      {
       conv_ip_count.insert(make_pair(conv_ip, 1));
       conv_ip_byte.insert(make_pair(conv_ip, header->caplen));
      }
      if(conv_mac_count.find(conv_mac) != conv_mac_count.end())
      {
          conv_mac_count[conv_mac]++;
          conv_mac_byte[conv_mac] += header->caplen;
      }
      else
      {
          conv_mac_count.insert(make_pair(conv_mac, 1));
          conv_mac_byte.insert(make_pair(conv_mac, header->caplen));
      }
  }

  for(auto it = ep_mac_receive_count.begin(); it != ep_mac_receive_count.end(); it++)
  {
    if(mac_container.find(it->first) == mac_container.end())
    {

        mac_container.insert({it->first, new Container(it->second, 0, 0, 0 )});

    }
    else
    {
        mac_container[it->first]->plus_recv_count(it->second);
    }
  }

  for(auto it = ep_mac_receive_byte.begin(); it != ep_mac_receive_byte.end(); it++)
  {
    if(mac_container.find(it->first) == mac_container.end())
    {

        mac_container.insert({it->first, new Container(0, it->second, 0, 0)});

    }
    else
    {
        mac_container[it->first]->plus_recv_bytes(it->second);
    }
  }

  for(auto it = ep_mac_send_count.begin(); it != ep_mac_send_count.end(); it++)
  {
    if(mac_container.find(it->first) == mac_container.end())
    {

        mac_container.insert({it->first, new Container(0, 0, it->second, 0 )});

    }
    else
    {
        mac_container[it->first]->plus_send_count(it->second);
    }
  }

  for(auto it = ep_mac_send_byte.begin(); it != ep_mac_send_byte.end(); it++)
  {
    if(mac_container.find(it->first) == mac_container.end())
    {

        mac_container.insert({it->first, new Container(0, 0, 0, it->second)});

    }
    else
    {
        mac_container[it->first]->plus_send_bytes(it->second);
    }
  }

  for(auto it = ep_ip_receive_count.begin(); it != ep_ip_receive_count.end(); it++)
  {
    if(ip_container.find(it->first) == ip_container.end())
    {

        ip_container.insert({it->first, new Container(it->second, 0, 0, 0 )});

    }
    else
    {
        ip_container[it->first]->plus_recv_count(it->second);
    }
  }

  for(auto it = ep_ip_receive_byte.begin(); it != ep_ip_receive_byte.end(); it++)
  {
    if(ip_container.find(it->first) == ip_container.end())
    {

        ip_container.insert({it->first, new Container(0, it->second, 0, 0)});

    }
    else
    {
        ip_container[it->first]->plus_recv_bytes(it->second);
    }
  }

  for(auto it = ep_ip_send_count.begin(); it != ep_ip_send_count.end(); it++)
  {
    if(ip_container.find(it->first) == ip_container.end())
    {

        ip_container.insert({it->first, new Container(0, 0, it->second, 0 )});

    }
    else
    {
        ip_container[it->first]->plus_send_count(it->second);
    }
  }

  for(auto it = ep_ip_send_byte.begin(); it != ep_ip_send_byte.end(); it++)
  {
    if(ip_container.find(it->first) == ip_container.end())
    {

        ip_container.insert({it->first, new Container(0, 0, 0, it->second)});

    }
    else
    {
        ip_container[it->first]->plus_send_bytes(it->second);
    }
  }

  for(auto it = conv_mac_count.begin(); it != conv_mac_count.end(); it++)
  {
    Conv_MAC rev = it->first;
    char tmp[6];
    memcpy(tmp, rev.dmac, 6);
    memcpy(rev.dmac, rev.smac, 6);
    memcpy(rev.smac, tmp, 6);
    if(conv_mac_container.find(rev) != conv_mac_container.end())
    {
        conv_mac_container[rev]->recv_count += it->second;
    }
    else
    {

        if(conv_mac_container.find(it->first) == conv_mac_container.end())
        {
            Container* tmp = new Container(0,0,it->second,0);
            conv_mac_container.insert({it->first, tmp});
        }
        else
        {
            conv_mac_container[it->first]->plus_send_count(it->second);
        }
    }
  }
  for(auto it = conv_mac_byte.begin(); it != conv_mac_byte.end(); it++)
  {
    Conv_MAC rev = it->first;
    char tmp[6];
    memcpy(tmp, rev.dmac, 6);
    memcpy(rev.dmac, rev.smac, 6);
    memcpy(rev.smac, tmp, 6);
    if(conv_mac_container.find(rev) != conv_mac_container.end())
    {
        conv_mac_container[rev]->plus_recv_bytes(it->second);
    }
    else
    {

        if(conv_mac_container.find(it->first) == conv_mac_container.end())
        {

            conv_mac_container.insert({it->first, new Container(0, 0, 0, it->second)});

        }
        else
        {
            conv_mac_container[it->first]->plus_send_bytes(it->second);
        }

    }
  }
  for(auto it = conv_ip_count.begin(); it != conv_ip_count.end(); it++)
  {
    Conv_IP rev = it->first;
    uint32_t tmp;
    tmp = rev.dip;
    rev.dip = rev.sip;
    rev.sip = tmp;
    if(conv_ip_container.find(rev) != conv_ip_container.end())
    {
        conv_ip_container[rev]->plus_recv_count(it->second);
    }
    else
    {

        if(conv_ip_container.find(it->first) == conv_ip_container.end())
        {
            conv_ip_container.insert({it->first, new Container(0, 0, it->second, 0 )});
        }
        else
        {
            conv_ip_container[it->first]->plus_send_count(it->second);
        }
    }
  }
  for(auto it = conv_ip_byte.begin(); it != conv_ip_byte.end(); it++)
  {
    Conv_IP rev = it->first;
    uint32_t tmp;
    tmp = rev.dip;
    rev.dip = rev.sip;
    rev.sip = tmp;
    if(conv_ip_container.find(rev) != conv_ip_container.end())
    {
        conv_ip_container[rev]->plus_recv_bytes(it->second);
    }
    else
    {

        if(conv_ip_container.find(it->first) == conv_ip_container.end())
        {
            conv_ip_container.insert({it->first, new Container(0, 0, 0, it->second)});
        }
        else
        {
            conv_ip_container[it->first]->plus_send_bytes(it->second);
        }
    }
  }


  printf("Endpoints - Ethernet\n");
  printf("Address\t\t\t\tPackets\t\tBytes\t\tTx Packet\tTx Bytes\tRx Packet\tRx Bytes\n");
  for(auto it = mac_container.begin(); it != mac_container.end(); it++)
  {
      printf("%02X-%02X-%02X-%02X-%02X-%02X\t\t", it->first.Mac_add[0] & 0xff, it->first.Mac_add[1] & 0xff, it->first.Mac_add[2] & 0xff, it->first.Mac_add[3] & 0xff, it->first.Mac_add[4] & 0xff, it->first.Mac_add[5] & 0xff);
      printf("%d\t\t", it->second->recv_count + it->second->send_count);
      printf("%d\t\t", it->second->recv_bytes + it->second->send_bytes);
      printf("%d\t\t", it->second->send_count);
      printf("%d\t\t", it->second->send_bytes);
      printf("%d\t\t", it->second->recv_count);
      printf("%d\n"  , it->second->recv_bytes);
  }
  printf("Endpoints - IP\n");
  printf("Address\t\tPackets\t\tBytes\t\tTx Packet\tTx Bytes\tRx Packet\tRx Bytes\n");
  for(auto it = ip_container.begin(); it != ip_container.end(); it++)
  {
      printf("%d.%d.%d.%d\t", (it->first & 0xff000000) >> 24, (it->first & 0xff0000) >> 16, (it->first & 0xff00) >> 8, it->first & 0xff);
      printf("%d\t\t", it->second->recv_count + it->second->send_count);
      printf("%d\t\t", it->second->recv_bytes + it->second->send_bytes);
      printf("%d\t\t", it->second->send_count);
      printf("%d\t\t", it->second->send_bytes);
      printf("%d\t\t", it->second->recv_count);
      printf("%d\n", it->second->recv_bytes);
  }
  printf("Conversations - Ethernet\n");
  printf("Address A\t\tAddress B\t\tPackets\t\tBytes\t\tPackets A to B\t\tBytes A to B\t\tPackets B to A\t\tBytes B to A\n");
  for(auto it = conv_mac_container.begin(); it != conv_mac_container.end(); it++)
  {
      printf("%02X-%02X-%02X-%02X-%02X-%02X\t", it->first.smac[0] & 0xff, it->first.smac[1] & 0xff, it->first.smac[2] & 0xff, it->first.smac[3] & 0xff, it->first.smac[4] & 0xff, it->first.smac[5] & 0xff);
      printf("%02X-%02X-%02X-%02X-%02X-%02X\t", it->first.dmac[0] & 0xff, it->first.dmac[1] & 0xff, it->first.dmac[2] & 0xff, it->first.dmac[3] & 0xff, it->first.dmac[4] & 0xff, it->first.dmac[5] & 0xff);
      printf("%d\t\t", it->second->recv_count + it->second->send_count);
      printf("%d\t\t", it->second->recv_bytes + it->second->send_bytes);
      printf("%d\t\t\t", it->second->send_count);
      printf("%d\t\t\t", it->second->send_bytes);
      printf("%d\t\t\t", it->second->recv_count);
      printf("%d\n", it->second->recv_bytes);
  }
  printf("Conversations - IP\n");
  printf("Address A\tAddress B\tPackets\t\tBytes\t\tPackets A to B\t\tBytes A to B\t\tPackets B to A\t\tBytes B to A\n");
  for(auto it = conv_ip_container.begin(); it != conv_ip_container.end(); it++)
  {
      printf("%d.%d.%d.%d\t", (it->first.sip & 0xff000000) >> 24, (it->first.sip & 0xff0000) >> 16, (it->first.sip & 0xff00) >> 8, it->first.sip & 0xff);
      printf("%d.%d.%d.%d\t", (it->first.dip & 0xff000000) >> 24, (it->first.dip & 0xff0000) >> 16, (it->first.dip & 0xff00) >> 8, it->first.dip & 0xff);
      printf("%d\t\t", it->second->recv_count + it->second->send_count);
      printf("%d\t\t", it->second->recv_bytes + it->second->send_bytes);
      printf("%d\t\t\t", it->second->send_count);
      printf("%d\t\t\t", it->second->send_bytes);
      printf("%d\t\t\t", it->second->recv_count);
      printf("%d\n", it->second->recv_bytes);
  }

}
