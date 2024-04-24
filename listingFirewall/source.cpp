#include "FirewallHeader.h"

//https://www.rhyous.com/2011/11/13/how-to-read-a-pcap-file-from-wireshark-with-c/
//https://www.tcpdump.org/pcap.html
//https://wiki.wireshark.org/SampleCaptures
//https://stackoverflow.com/questions/5237486/how-to-write-pcap-capture-file-header
// //https://dev.to/10xlearner/magic-numbers-and-how-to-deal-with-them-in-c-2jbn
// https://github.com/strobejb/sslhook/blob/master/sslhook/pcap.cpp
// https://www.youtube.com/watch?v=lS6o0oeiGNs
    //atm_capture1.cap


int main(int argc, char* argv[]) {

    //windows socket data 
    //network capabilities for firewall creation 
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }


    if (strcmp(argv[1], "file") == 0 && argc < 3) {
        std::cerr << "Usage: pcapFirewall.exe file <pcap file> <option>\n";
        CALL();
        return 1;
    }

    char errorBuffer[PCAP_ERRBUF_SIZE]; 

    //poen saved pcap... if it cant be pened pen error
    pcap_t* pcap = pcap_open_offline(argv[2], errorBuffer);
    if (pcap == NULL) {
        std::cerr << "Error opening pcap file: " << errorBuffer << std::endl;
        return -1;
    }
    if (strcmp(argv[3], "--GET") == 0)
    {
        //process the packets until all packets are read
        if (pcap_loop(pcap, 0, packetHandlerGET, NULL) < 0) {
            std::cerr << "Error during  GET Requests: " << pcap_geterr(pcap) << std::endl;
            return -1;
        }
    }

    if (strcmp(argv[3], "--magic") == 0)
    {
        //process the packets until all packets are read
        if (pcap_loop(pcap, 0, packetHandlerMAGIC, NULL) < 0) {
            std::cerr << "Error during MagicNumber Requests: " << pcap_geterr(pcap) << std::endl;
            return -1;
        }
    }

    if (strcmp(argv[3], "--ipA") == 0 && argc >= 5) {

        if (pcap_loop(pcap, 0, packetHandlerIP, (u_char*)argv[4]) < 0) {
            std::cerr << "Error processing IP address: " << pcap_geterr(pcap) << std::endl;
            return -1;
        }

    }

    if (strcmp(argv[3], "--block") == 0 && argc >= 5) { //this loops through all the pcaps tho.... makes a large denyu listing 

        if (pcap_loop(pcap, 0, packetHandlerBlock, (u_char*)argv[4]) < 0) {
            std::cerr << "pcap_loop() failed to block: " << pcap_geterr(pcap) << std::endl;
            return -1;
        }

    }

    if (strcmp(argv[3], "--allow") == 0 && argc >= 5) {//this loops through all the pcaps tho.... makes a large allow listing 

        if (pcap_loop(pcap, 0, packetHandlerAllow, (u_char*)argv[4]) < 0) {
            std::cerr << "pcap_loop() failed allow: " << pcap_geterr(pcap) << std::endl;
            return -1;
        }

    }

    WSACleanup();
    pcap_close(pcap);
    return 0;
}

