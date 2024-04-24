#include "FirewallHeader.h"

void CALL() {

    wcerr << L"Usage: firewall.exe file <pcap file> [options]\n"
        << L"Options:\n"
        << L" --GET          Filtering for the HTTP GET request in pcap file\n"
        << L" --magic        Filtering for the magic numbers in the pcap file\n"
        << L" --ipA          Filtering for a specific ip address in a pcap file\n"
        << L" --block        Block ip address and add to firewall rules\n"
        << L" --allow        Allow ip address and add to firewall rules\n"
        ;

}

//////////////////////////////////////////////////////////////////////////////////signature detectin///////////////////////////////////////////////////////////////////////////////////////////////
//need t build your own ip header structure
    //https://stackoverflow.com/questions/32401277/c-structure-declaration-and-usage-to-hold-ip-connections
    //https://codereview.stackexchange.com/questions/216894/modeling-an-ipv4-address
    //https://stackoverflow.com/questions/5328070/how-to-convert-string-to-ip-address-and-vice-versa

// IP header structure
struct ip_hdr {
    unsigned char  ip_header_len : 4; // IP header length
    unsigned char  ip_version : 4;    // Version of IP
    unsigned short ip_total_length; // Total length

    unsigned char  ip_protocol;        // Protocol(TCP,UDP etc)
    unsigned short ip_checksum;        // IP checksum
    unsigned int   ip_srcaddr;         // Source address
    unsigned int   ip_destaddr;        // des address
};

//check multiple magic numbers,... structs
//store info about sequence
struct MagicNumber {
    std::vector<unsigned char> bytes; //sequence f the bytes
    std::string description; //the text description of the byte 
};

// Function to check for the presence of magic numbers in packet data
std::string containsMagicNumber(const u_char* packet, size_t len, const std::vector<MagicNumber>& magicNumbers) {

    //iterate through magic number
    for (const auto& mn : magicNumbers) {

        //check length bc if the packet is less than the length of the magic number then skip the function
        if (len < mn.bytes.size()) 
            continue;

        //search the packet for each magic number within packet in every position starting from 0 to length of packet - magic number length
        for (size_t i = 0; i <= len - mn.bytes.size(); ++i) {
            bool match = true;

            //for each poisition check each magic number byte 
            for (size_t j = 0; j < mn.bytes.size(); ++j) {
                //check the magic number to the packet position if they all match 
                if (packet[i + j] != mn.bytes[j]) {
                    //if it don't match exit
                    match = false;
                    break;
                }
            }
            // if match then return the description from the magic number strct
            if (match) {
                return mn.description;
            }
        }
    }
    return "";
}

void packetHandlerMAGIC(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    //magic number detection hard coded in 
    std::vector<MagicNumber> magicNumbers = {
        {{0x47, 0x49, 0x46, 0x38}, "GIF image files"},
        {{0xFF, 0xD8, 0xFF, 0xE0}, "JPEG image files"},
        {{0xFF, 0xD8, 0xFF, 0xDB}, "JPEG image files"},
        {{0x89, 0x50, 0x4E, 0x47}, "PNG image files"},
        {{0x25, 0x50, 0x44, 0x46}, "PDF documents"},
        {{0x50, 0x4B, 0x03, 0x04}, "ZIP files"},
        {{0x42, 0x4D}, "Bitmap image files"},
        {{0xD0, 0xCF, 0x11, 0xE0}, "Microsoft Office formats"},
        {{0xCA, 0xFE, 0xBA, 0xBE}, "Java class files"},
        {{0x7F, 0x45, 0x4C, 0x46}, "ELF files"},
        {{0x49, 0x49, 0x2A, 0x00}, "TIFF files"},
        {{0x4D, 0x4D, 0x00, 0x2A}, "TIFF files"},
        {{0x00, 0x00, 0x01, 0xBA}, "MPEG video files"},
        {{0x00, 0x00, 0x01, 0xB3}, "MPEG video files"}
    };

    //calls for the function that checks for the presence f magic number and if found prints that the magic number is found and prints which ne 
    std::string found = containsMagicNumber(packet, pkthdr->len, magicNumbers);

    //if string isn't empty print 

    if (!found.empty()) {

        std::cout << "Magic number detected: " << found << std::endl;

    }
}

// Packet handler function to process both HTTP GET requests and magic number detection 
//analyze networck packets
void packetHandlerGET(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    //HTTP GET Detection
    const char* payload = (const char*)(packet + 54); // skip the first 54 bytes f the packet... (ethernet, IP, and CTIP header)

    if (pkthdr->len > 54 && strstr(payload, "GET /") == payload) { //is it greater than 54 bytes ,,,, des it start with GET /

        std::cout << "HTTP GET request detected: ";

        //if it does iterate for first 100 characters until the new line and return are found 
        for (int i = 0; i < 100 && i < pkthdr->len - 54; i++) { // if detencted print the first line of request or until new line 

            char c = payload[i];

            if (c == '\r' || c == '\n')
                break;

            std::cout << c;
        }

        std::cout << std::endl;
    }
}


std::string getProtocolName(unsigned char protocol) {

    //switch statement to match protocol identifier 
    switch (protocol) {
        //iANA 
    case 1: return "ICMP"; // if protocol number is 1 
    case 6: return "TCP";
    case 17: return "UDP";
    default: return "Unknown";
    
    }
}

//netowrk monitor filter ip packetrs 
//https://stackoverflow.com/questions/21222369/getting-ip-address-of-a-packet-in-pcap-file
void packetHandlerIP(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    const int ethernetHeaderLength = 14; // Length of Ethernet header
    struct ip_hdr* ipHeader = (struct ip_hdr*)(packet + ethernetHeaderLength);//start of ip header 

    char sourceIp[INET_ADDRSTRLEN]; //hold source ip
    char destIp[INET_ADDRSTRLEN]; //hold destination ip 

    // Convert numeric IP addresses to string format using inet_ntop
    inet_ntop(AF_INET, &(ipHeader->ip_srcaddr), sourceIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_destaddr), destIp, INET_ADDRSTRLEN);

    //// Get the protocol
    std::string protocolName = getProtocolName(ipHeader->ip_protocol);

    char* targetIp = (char*)userData;  
    
    // Using the user data passed to filter specific IP addresses
    if (strcmp(sourceIp, targetIp) == 0 || strcmp(destIp, targetIp) == 0) {
        std::cout << "Packet from/to " << targetIp << " detected: ";
        std::cout << "Protocol: " << protocolName << ", Source IP: " << sourceIp << ", Destination IP: " << destIp << std::endl;
    }
}
/////////////////////////////////////////////////////////////////////////////////////////block to firewall//////////////////////////////////////////////////////////

//https://stackoverflow.com/questions/43678273/how-to-call-a-powershell-script-from-a-c-code
//https://www.sans.org/blog/windows-firewall-script-to-block-ip-addresses-and-country-network-ranges/
//block ip using th epowershell command 
void blockIP(const std::string& ip) {
    std::string command = "powershell -Command \"New-NetFirewallRule -DisplayName 'Block " + ip + "' -Direction Inbound -Action Block -RemoteAddress " + ip + "\"";
    system(command.c_str()); // in system's command shell 
}


//http://tonylukasavage.com/blog/2010/11/17/packet-capture-with-c----amp--linux/
//https://www.devdungeon.com/content/using-libpcap-c
void packetHandlerBlock(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    static bool ipBlocked = false;

    if (ipBlocked) {
        return; // Stop processing after first IP is blocked
    }

    // Extract IP address from the packet
    const struct ip_hdr* ipHeader = (const struct ip_hdr*)(packet + 14); // Ethernet header is 14 bytes
    char srcIP[INET_ADDRSTRLEN];//store string 

    inet_ntop(AF_INET, &(ipHeader->ip_srcaddr), srcIP, INET_ADDRSTRLEN);//convert ip from packet t readable string 

    std::cout << "Blocking IP: " << srcIP << std::endl;
    blockIP(srcIP);  // Block the IP
    ipBlocked = true;

    pcap_breakloop((pcap_t*)user); // Stop the pcap loop
}


///////////////////////////////////////////////////////////////////////////////////////allow firewall///////////////////////////////////////////////////////////////

// Allow an IP address through the firewall
void allowIP(const std::string& ip) {
    std::string command = "powershell -Command \"New-NetFirewallRule -DisplayName 'Allow " + ip + "' -Direction Inbound -Action Allow -RemoteAddress " + ip + "\"";
    system(command.c_str());
}


void packetHandlerAllow(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    static bool ipAllowed = false;

    if (ipAllowed) {
        return; // Stop processing after first IP is allowed
    }

    // Extract IP address from the packet
    const struct ip_hdr* ipHeader = (const struct ip_hdr*)(packet + 14); // Ethernet header is 14 bytes
    char srcIP[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->ip_srcaddr), srcIP, INET_ADDRSTRLEN);

    std::cout << "Allowing IP: " << srcIP << std::endl;
    allowIP(srcIP);  // Allow the IP
    ipAllowed = true;

    pcap_breakloop((pcap_t*)user); // Stop the pcap loop
}