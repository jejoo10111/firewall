#include <pcap.h> //network packet capture and analysis 
#include <iostream> 
#include <cstring>
#include <vector>
//https://learn.microsoft.com/en-us/windows/win32/api/_iphlp/
#include <winsock2.h> // used in network prorgramming to help with sockets, dns, network tasks
#include <Iphlpapi.h> //access to netwrk configurations 
#include <ws2tcpip.h>  // for inet_ntop

#pragma comment(lib, "Ws2_32.lib") // link to ws2_32.lib socket operations
#pragma comment(lib, "Iphlpapi.lib") // access to windows ip ... access network configurations and status of windows

using namespace std;

void CALL();

void packetHandlerGET(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void packetHandlerMAGIC(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void packetHandlerIP(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void blockIP(const std::string& ip);
void packetHandlerBlock(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void allowIP(const std::string& ip);
void packetHandlerAllow(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);

