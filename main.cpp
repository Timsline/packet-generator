/* Stark Erich 6041
Program na generovanie zadanych paketov

Zadanie 1 - KS2 FEI 2014
Navrhnite a implementujte program, ktory generuje pakety podla zadanych poziadaviek
a uklada ich do suboru. Pakety musia byt spravne rozpoznane programom Wireshark.   
 
 Spresnenie zadania: 
Pri vytvarani paketu, si program nacita konfiguracny XML subor kde budu potrebne informacie 
na zostavenie paketov v zavislosti na type protokolu.  
Je  nutne nastavit vsetky nastavenia z konfiguracneho suboru.  
Vyznam tagov v sablone:  
<packet_summary> uvodny tag pre zaciatok celeho konfiguracneho nastavenia 
<item> zaciatok noveho paketu 
<index> poradove cislo paketu 
<frame_type> typ ramca (Ethernet, 802.3 )  
<local_mac_address> zdrojova  MAC adresa (vzor formatu : 00-1d-60-45-59-07) 
<remote_mac_address> cielová MAC adresa (vzor formatu : 00-1d-60-45-59-07) 
<protocol> typ vnorenych protokolov zo sietovej a transportnej (IP,IPX,TCP,UDP) 
<version> verzia protokolu (4,6) 
<local_address> zdrojova IP adresa pri protokole IP v dekadickom tvare 
<remote_address> cielova IP adresa pri protokole IP v dekadickom tvare   
<local_net_address> zdrojova sietova adresa pri IPX protokole v hexa tvare 
<local_socket_address> zdrojovy port pri IPX protokole v hexa tvare  
<remote_net_address> cielova sietová adresa pri IPX protokole v hexa tvare  
<remote_socket_address> cielovy port pri IPX protokole v hexa tvare        
<protocol_type> typ vnoreneho protokolu 
<local_port> zdrojovy port v dekadickom tvare 
<remote_port> cielovy port v dekadickom tvare 
<packets> pocet generovanych paketov daneho typu  
 
Blizsie poziadavky: 
- Ak je vnoreny protokol IP treba  nastavit dalsie parametre potrebne ku spravnej identifikacii 
 paketu (staci default hodnoty- ide napr. o TTL, flags, total length, atd.). Kontrolny sucet
 sa hodnoti ako bonus (header checksum).    
- Ak je vnoreny protokol TCP, UDP treba nastavit dalsie parametre potrebne ku spravnej identifikacii
 paketu (napr. priznak, okno, velkost...stací default hodnoty ). Vypocet kontrolneho suctu je povinny. 
- Pri vnorenom IPX protokole nastavit default hodnoty pre dlzku paketu, transport kontrol, aby bol paket
 spravne identifikovany. 
- Pri type ramca 802.3 neriesit SNAP a 802.2 iba IPX. 
- Program musi ukladat pakety jednotlivo, alebo viac naraz. 

Kazda cast aplikacie musi po spusteni svoju cinnost zdokumentovat pomocou sprav o prave vykonanych ulohach
napr. Nacitam obsah suboru s nazvom ..., Nacitanie suboru ... prebehlo v poriadku, Analyzujem hlavicku,
Vypocitam CRC. Porovnavam CRC. Paket podla CRC dorazil neporusene, atd.   texty sprav kazdy student upravi
podla potreby vlastnej implementacie!!!).

Riesenie:
Zoznam pouzitych premennych a ich komentovany vyznam (vyplnit podla vasho kodu!!! napr. SA - zdrojova adresa paketu):

vsetky premenne mam pochopitelne pomenovane

*/


/*
 *   Author: Erich Stark
 *
 *   2014
 * 
 * 
 *   Licence: GPLv3
 */

#include <stdio.h>    // to get "printf" function
#include <stdlib.h>   // to get "free" function
#include <iostream>
#include <fstream>
#include <string.h>
#include <string>
#include "xmlparser.h"

#include <regex>
#include <iterator>
#include <unistd.h>

#include <pcap.h>

using namespace std;

string const UDP("UDP");
string const TCP("TCP");
string const PEP("PEP");


#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

// setup
int const IPv4(0x45);

int str_to_int(string text) {
    return stoi(text, NULL, 16);
}

int str_to_int(string text, int base) {
    return stoi(text, NULL, base);
}

string parse_mac_address(string mac_address) {
    auto it = std::remove_if(std::begin(mac_address), std::end(mac_address), [](char c) {
        return (c == '-');
    });
    mac_address.erase(it, std::end(mac_address));

    return mac_address;

}

string parse_ipx_items(string ipx_item) {
    auto it = std::remove_if(std::begin(ipx_item), std::end(ipx_item), [](char c) {
        return (c == ' ');
    });
    ipx_item.erase(it, std::end(ipx_item));

    return ipx_item;
}

u_char* parse_ip_addr(string ip_address) {
    char ip1[3] = "";
    char ip2[3] = "";
    char ip3[3] = "";
    char ip4[3] = "";
    u_char* ip;
    ip = (u_char*) malloc((4)*1);

    int count = 0;
    int j = 0;
    for (int i = 0; i < ip_address.length(); i++) {

        if (ip_address[i] == '.') {
            count++;
            j = -1;

        } else {
            if (count == 0)ip1[j] = ip_address[i];
            else if (count == 1) ip2[j] = ip_address[i];
            else if (count == 2) ip3[j] = ip_address[i];
            else if (count == 3) ip4[j] = ip_address[i];
        }
        j++;
    }
    //nastavenie cielovej adresy

    ip[0] = atoi(ip1);
    ip[1] = atoi(ip2);
    ip[2] = atoi(ip3);
    ip[3] = atoi(ip4);

    return ip;
}

string dec_to_hexstr(string dec_str) {
    string result;
    long int decimalNumber = str_to_int(dec_str, 10);
    long int quotient;
    int temp;

    quotient = decimalNumber;

    while (quotient != 0) {
        temp = quotient % 16;

        //To convert integer into character
        if (temp < 10)
            temp = temp + 48;
        else
            temp = temp + 55;

        result += temp;
        quotient = quotient / 16;
    }

    if (result.length() == 1) {
        result += "000";
    } else if (result.length() == 2) {
        result += "00";
    } else if (result.length() == 3) {
        result += "0";
    }

    return string(result.rbegin(), result.rend());
}

u_char* setup_ipx_packet(int size_of_packet,
        string local_mac_address,
        string remote_mac_address,
        string local_net_address,
        string remote_net_address,
        string local_socket_address,
        string remote_socket_address) {

    u_char* packet;
    packet = (u_char*) malloc((size_of_packet)*1);


    // 802.3 header

    // destination mac 00-03-ba-9a-15-63
    string remote_mac_address_new = parse_mac_address(remote_mac_address);
    int j = 0;
    for (int i = 0; i <= 5; i++) {
        packet[i] = str_to_int(remote_mac_address_new.substr(j, 2)); // destination node 802.3
        packet[i + 24] = str_to_int(remote_mac_address_new.substr(j, 2)); // destination node IPX
        j += 2;
    }

    // source mac 00-1d-60-45-59-07
    string local_mac_address_new = parse_mac_address(local_mac_address);
    j = 0;
    for (int i = 6; i <= 11; i++) {
        packet[i] = str_to_int(local_mac_address_new.substr(j, 2)); // source node 802.3
        packet[i + 30] = str_to_int(local_mac_address_new.substr(j, 2)); // source node IPX
        j += 2;
    }

    // lenght 0x01b0 kvoli identifikacii 
    packet[12] = 0x00;
    packet[13] = 0x20; // dlzka dat (ipx cele 32 dec)

    //end header

    // checksum musi byt 0xffff
    packet[14] = 0xff;
    packet[15] = 0xff;

    // ipx packet lenght max 0x01b0
    packet[16] = 0x00;
    packet[17] = 0x4e; // 3e

    // transport control
    packet[18] = 0x03; // 3 hops

    // packet type pep 0x04
    packet[19] = 0x04;

    // destination network 30 09 80 00
    string remote_net_address_new = parse_ipx_items(remote_net_address);
    j = 0;
    for (int i = 20; i <= 23; i++) {
        packet[i] = str_to_int(remote_net_address_new.substr(j, 2));
        j += 2;
    }

    // destination socket 04 53
    string remote_socket_address_new = parse_ipx_items(remote_socket_address);
    packet[30] = str_to_int(remote_socket_address_new.substr(0, 2));
    packet[31] = str_to_int(remote_socket_address_new.substr(2, 2));

    // source network 30 09 80 00
    string local_net_address_new = parse_ipx_items(local_net_address);
    j = 0;
    for (int i = 32; i <= 35; i++) {
        packet[i] = str_to_int(local_net_address_new.substr(j, 2));
        j += 2;
    }

    // source socket 04 53
    string local_socket_address_new = parse_ipx_items(local_socket_address);
    packet[42] = str_to_int(local_socket_address_new.substr(0, 2));
    packet[43] = str_to_int(local_socket_address_new.substr(2, 2));

    for (int i = 44; i <= 60; i++) {
        packet[i] = 0x00;
    }

    // set request or response 0x0002
    packet[44] = 0x00;
    packet[45] = 0x01;

    return packet;
}

u_char* setup_udp_packet(int size_of_packet,
        string local_mac_address,
        string remote_mac_address,
        string version,
        string local_address,
        string remote_address,
        string protocol_type,
        string local_port,
        string remote_port,
        string service_name) {

    u_char* packet;
    packet = (u_char*) malloc((size_of_packet)*1);


    // set destination MAC
    string remote_mac_address_new = parse_mac_address(remote_mac_address);
    int j = 0;

    for (int i = 0; i <= 5; i++) {
        packet[i] = str_to_int(remote_mac_address_new.substr(j, 2));
        j += 2;
    }

    // set source MAC
    j = 0;
    string local_mac_address_new = parse_mac_address(local_mac_address);
    for (int i = 6; i <= 11; i++) {
        packet[i] = str_to_int(local_mac_address_new.substr(j, 2));
        j += 2;
    }

    // set IP protocol 0x0800
    packet[12] = 0x08;
    packet[13] = 0x00;

    // IPv4 = 0x45
    packet[14] = IPv4;

    // diff services field
    packet[15] = 0x00;

    // length IP
    packet[16] = 0x00;
    packet[17] = 0x28; // 40 bytes

    // identification
    packet[18] = 0x00;
    packet[19] = 0x00;

    // flags
    packet[20] = 0x40; // dont fragment

    // fragment offset
    packet[21] = 0x00;

    // Time To Live - TTL  128?
    packet[22] = 0x80;

    // protocol UDP
    packet[23] = 0x11;

    // IP header checksum
    packet[24] = 0x00;
    packet[25] = 0x00;

    // IP source address
    u_char* ipcko_local = parse_ip_addr(local_address);

    for (int i = 26; i <= 29; i++) {
        packet[i] = ipcko_local[i - 26];
    }

    // IP destination address
    u_char* ipcko_remote = parse_ip_addr(remote_address);

    for (int i = 30; i <= 33; i++) {
        packet[i] = ipcko_remote[i - 30];
    }

    // check sum 
    uint32_t sum_ip = 0;
    uint16_t word_ip;

    for (int i = 14; i <= 33; i += 2) {
        word_ip = ((packet[i] << 8) & 0xff00) + (packet[i + 1] & 0xff);
        sum_ip += (uint32_t) word_ip;
    }

    while (sum_ip >> 16)
        sum_ip = (sum_ip & 0xffff) + (sum_ip >> 16);

    sum_ip = ~sum_ip;
    
    packet[24] = (sum_ip & 0xff00) >> 8;
    packet[25] = sum_ip & 0xff;
    
    cout << GREEN << "[OK]" << RESET << " Vypocitany checksum pre IP hlavicku UDP" << endl;
    
    // UDP information
    // udp source port
    string local_port_new = dec_to_hexstr(local_port); // 44 5c
    packet[34] = str_to_int(local_port_new.substr(0, 2)); // D8E6
    packet[35] = str_to_int(local_port_new.substr(2, 2));



    string remote_port_new = dec_to_hexstr(remote_port);
    // udp destination port
    packet[36] = str_to_int(remote_port_new.substr(0, 2)); // 35
    packet[37] = str_to_int(remote_port_new.substr(2, 2));

    // udp length
    packet[38] = 0x00;
    packet[39] = 0x14; // 20 bytes

    // check sum
    packet[40] = 0x5a;
    packet[41] = 0x11;


    // data 50:69:76:61:72:6e:69:6b:20:6a:65:20:68:6f:6d:6f:73:20:3a:44
    packet[42] = 0x00;
    packet[43] = 0x00;
    packet[44] = 0x00;
    packet[45] = 0x00;

    packet[46] = 0x00;
    packet[47] = 0x00;
    packet[48] = 0x00;
    packet[49] = 0x00;
    packet[50] = 0x00;
    packet[51] = 0x00;
    packet[52] = 0x00;
    packet[53] = 0x00;

    packet[54] = 0x00;
    packet[55] = 0x00;
    packet[56] = 0x00;
    packet[57] = 0x00;
    packet[58] = 0x00;
    packet[59] = 0x00;
    packet[60] = 0x00;
    packet[61] = 0x00;


    uint32_t sum = 0;
    uint16_t word;
    int i;

    for (i = 26; i <= 39; i += 2) {
        word = ((packet[i] << 8) & 0xff00) + (packet[i + 1] & 0xff);
        sum += (uint32_t) word;
    }

    sum += 17 + 40 - 20;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    sum = ~sum;

    packet[40] = (sum & 0xff00) >> 8;
    packet[41] = sum & 0xff;
    cout << GREEN << "[OK]" << RESET << " Vypocitany checksum pre UDP" << endl;

    return packet;
}

u_char* setup_tcp_packet(int size_of_packet,
        string local_mac_address,
        string remote_mac_address,
        string version,
        string local_address,
        string remote_address,
        string protocol_type,
        string local_port,
        string remote_port,
        string service_name) {

    u_char* packet;
    packet = (u_char*) malloc((size_of_packet)*1);

    // mac destination address to 00-00-00-00-00-00
    string remote_mac_address_new = parse_mac_address(remote_mac_address);
    int j = 0;
    for (int i = 0; i <= 5; i++) {
        packet[i] = str_to_int(remote_mac_address_new.substr(j, 2));
        j += 2;
    }

    // set mac source address to 00-21-85-11-29-1b
    string local_mac_address_new = parse_mac_address(local_mac_address);
    j = 0;
    for (int i = 6; i <= 11; i++) {
        packet[i] = str_to_int(local_mac_address_new.substr(j, 2));
        j += 2;
    }


    // set IP protocol 0x0800
    packet[12] = 0x08;
    packet[13] = 0x00;

    // IPv4 = 0x45
    packet[14] = IPv4;

    // differentiated services field
    packet[15] = 0x00;

    // length IP
    packet[16] = 0x00;
    packet[17] = 0x28; // 40 bytes

    // identification 3a50
    packet[18] = 0x00;
    packet[19] = 0x00;

    // flags
    packet[20] = 0x40; // dont fragment

    // fragment offset
    packet[21] = 0x00;

    // Time To Live - TTL  128?
    packet[22] = 0x80;

    // protocol TCP
    packet[23] = 0x06;

    // ip header checksum // TODO
    packet[24] = 0x00;
    packet[25] = 0x00;

    // IP source address
    u_char* ipcko_local = parse_ip_addr(local_address);

    for (int i = 26; i <= 29; i++) {
        packet[i] = ipcko_local[i - 26];
    }

    // IP destination address
    u_char* ipcko_remote = parse_ip_addr(remote_address);
    for (int i = 30; i <= 33; i++) {
        packet[i] = ipcko_remote[i - 30];
    }

    uint32_t sum_ip = 0;
    uint16_t word_ip;

    for (int i = 14; i <= 33; i += 2) {
        word_ip = ((packet[i] << 8) & 0xff00) + (packet[i + 1] & 0xff);
        sum_ip += (uint32_t) word_ip;
    }

    while (sum_ip >> 16)
        sum_ip = (sum_ip & 0xffff) + (sum_ip >> 16);

    sum_ip = ~sum_ip;

    packet[24] = (sum_ip & 0xff00) >> 8;
    packet[25] = sum_ip & 0xff;
    
    cout << GREEN << "[OK]" << RESET << " Vypocitany checksum pre IP hlavicku TCP" << endl;

    // TCP information
    // TCP source port
    string local_port_new = dec_to_hexstr(local_port);
    packet[34] = str_to_int(local_port_new.substr(0, 2));
    packet[35] = str_to_int(local_port_new.substr(2, 2));

    // TCP destination port
    string remote_port_new = dec_to_hexstr(remote_port);
    packet[36] = str_to_int(remote_port_new.substr(0, 2));
    packet[37] = str_to_int(remote_port_new.substr(2, 2));

    // TCP sequence number: 0 (relative) example: 0x1626d405
    packet[38] = 0x00;
    packet[39] = 0x00;
    packet[40] = 0x00;
    packet[41] = 0x00;


    // acknowledgment number : 1 example: 0x59042021
    packet[42] = 0x00;
    packet[43] = 0x00;
    packet[44] = 0x00;
    packet[45] = 0x00;

    // tcp header lenght
    packet[46] = 0x50; // 20 bytes

    // flags 0x01f - prenastavene na 0x00 lebo mi nesedelo FTP vo wiresharku
    packet[47] = 0x00; // flags

    // window size
    packet[48] = 0x01; // example number
    packet[49] = 0x00;

    // checksum
    packet[50] = 0x00;
    packet[51] = 0x00;

    // urgent pointer
    packet[52] = 0x00;
    packet[53] = 0x00;

    // 54-65 options

    // no operation
    packet[54] = 0x00;
    packet[55] = 0x00;

    packet[56] = 0x00;
    packet[57] = 0x00;
    packet[58] = 0x00;
    packet[59] = 0x00;
    packet[60] = 0x00;
    packet[61] = 0x00;
    packet[62] = 0x00;
    packet[63] = 0x00;
    //packet[64] = 0x00;
    //packet[65] = 0x00;

    uint32_t sum = 0;
    uint16_t word;
    int i;

    for (i = 26; i <= 49; i += 2) {
        word = ((packet[i] << 8) & 0xff00) + (packet[i + 1] & 0xff);
        sum += (uint32_t) word;
    }

    sum += 6 + 40 - 20;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    sum = ~sum;

    packet[50] = (sum & 0xff00) >> 8;
    packet[51] = sum & 0xff;
    
    cout << GREEN << "[OK]" << RESET << " Vypocitany checksum pre TCP" << endl;
    
    return packet;
}

string set_broadcast_mac_address() {
    return "00-00-00-00-00-00";
}

void info_program() {
    cout << CYAN << endl;
    for (int i = 0; i < 80; i++) {
        cout << "*";
    }
    cout << endl;
    cout << "*" << "                           " << "Generator packetov " << "                                *" << endl;
    cout << "*" << "                           " << "Author: Erich Stark" << "                                *" << endl;
    cout << "*" << "                           " << "FEI STU: API 2013/2014 " << "                            *" << endl;
    cout << "*" << "                           " << "Komunikacne siete 2" << "                                *" << endl;
    cout << "*" << "                           " << "Vytvorene na OS: Fedora 20" << "                         *" << endl;
    cout << "*" << "                           " << "libpcap ver: 1.5.3-1" << "                               *" << endl;
    for (int i = 0; i < 80; i++) {
        cout << "*";
    }
    cout << RESET << endl;
}

int main(int argc, char **argv) {
    string index;
    string frame_type;
    string local_mac_address;
    string remote_mac_address;
    string protocol;
    string version;
    string local_address;
    string remote_address;
    string protocol_type;
    string local_port;
    string remote_port;
    string service_name;
    string packets;

    //ipx
    string local_net_address;
    string local_socket_address;
    string remote_net_address;
    string remote_socket_address;
    
    // info o programe
    info_program();
    
    cout << GREEN << "[OK]" << RESET << " Vytvorene premenne pre XML" << endl;

    char pcap_name[] = "packet.pcap";
    char* xml_name;



    char *cvalue = NULL;
    int index1;
    int c;

    while ((c = getopt(argc, argv, "f:")) != -1)
        switch (c) {
                //            case 'b':
                //                bflag = 13;
                //                break;
            case 'f':
                cvalue = optarg;
                xml_name = (char*) malloc((strlen(optarg))*1);
                xml_name = optarg;
                break;
            case '?':
                if (optopt == 'f')
                    fprintf(stderr, "Spravne volanie: %s -%c <filename>\n", argv[0], optopt);
                else if (isprint(optopt))
                    fprintf(stderr, "Neznamy parameter `-%f'.\n", optopt);
                else
                    fprintf(stderr,
                        "Neznamy znak `\\x%x'.\n",
                        optopt);
                return 1;
            default:
                abort();
        }

    if (argc < 2) {
        xml_name = (char*) malloc(12);
        strcpy(xml_name, "packets.xml");
    } 
         
        
    for (index1 = optind; index1 < argc; index1++)
        printf("Non-option argument %s\n", argv[index1]);

    
        
    pcap_t *pcap_dead_ip;
    pcap_dumper_t *pcap_dump_ip;

    pcap_dead_ip = pcap_open_dead(DLT_EN10MB, 65535);

    // create the output file
    pcap_dump_ip = pcap_dump_open(pcap_dead_ip, pcap_name);

    cout << GREEN << "[OK]" << RESET << " Vytvoreny vystupny subor pre wireshark: " << pcap_name << endl << endl;
    
    timeval *ts = (timeval*) malloc(sizeof (timeval));
    ts->tv_sec = time(NULL);
    ts->tv_usec = 0;

    //creation of header
    pcap_pkthdr *header = (pcap_pkthdr*) malloc(sizeof (pcap_pkthdr));
    header->caplen = 62;
    header->len = 62;
    header->ts = *ts;

    cout << GREEN << "[OK]" << RESET << " Vytvoreny header pre pcap s velkostou: " << header->caplen << endl << endl;

    // this open and parse the XML file:
    XMLNode xMainNode = XMLNode::openFileHelper(xml_name, "packets_summary");

    cout << GREEN << "[OK]" << RESET << " Nacitany XML subor: " << xml_name << endl << endl;
    
    
    int count_items = xMainNode.nChildNode();

    for (int i = 0; i < count_items; i++) {
        XMLNode node = xMainNode.getChildNode(i);
        cout << YELLOW << "[Start]" << RESET << " Nacitavanie dat z XML" << endl;
        
        index = node.getChildNode("index").getText();
        cout << GREEN << "[OK]" << RESET << " Nacitany index: " << index << endl;
        
        protocol = node.getChildNode("protocol").getText();
        cout << GREEN << "[OK]" << RESET << " Nacitany protocol: " << protocol << endl;
        
        protocol_type = node.getChildNode("protocol_type").getText();
        cout << GREEN << "[OK]" << RESET << " Nacitany protocol_type: " << protocol_type << endl;
        
        local_mac_address = node.getChildNode("local_mac_address").getText();
        cout << GREEN << "[OK]" << RESET << " Nacitane local_mac_address: " << local_mac_address << endl;
        
        if (node.getChildNode("remote_mac_address").getText() != NULL) {
            remote_mac_address = node.getChildNode("remote_mac_address").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane remote_mac_address: " << remote_mac_address << endl;
        } else {
            remote_mac_address = set_broadcast_mac_address();
            cout << GREEN << "[OK]" << RESET << " remote_mac_address je prazdna, nastavujem: " << remote_mac_address << endl;
        }
        
        
        frame_type = node.getChildNode("frame_type").getText();
        cout << GREEN << "[OK]" << RESET << " Nacitany frame_type: " << frame_type << endl;

        if (!protocol_type.compare(UDP) || !protocol_type.compare(TCP)) {
            cout << YELLOW << "[UDP/TCP]" << RESET << " Specificke udaje pre UDP/TCP: " << endl;
            version = node.getChildNode("version").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane version: " << version << endl;
            
            local_address = node.getChildNode("local_address").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane local_address: " << local_address << endl;
            
            remote_address = node.getChildNode("remote_address").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane remote_address: " << remote_address << endl;
            
            local_port = node.getChildNode("local_port").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane local_port: " << local_port << endl;
            
            remote_port = node.getChildNode("remote_port").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane remote_port: " << remote_port << endl;
            
            if (node.getChildNode("service_name").getText() != NULL) {
                service_name = node.getChildNode("service_name").getText();
            } else {
                service_name = "";
            }
            cout << GREEN << "[OK]" << RESET << " Nacitane service_name: " << service_name << endl;

        } else if (!protocol_type.compare(PEP)) {
            cout << YELLOW << "[PEP]" << RESET << " Specificke udaje pre (IPX) PEP: " << endl;
            
            local_net_address = node.getChildNode("local_net_address").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane local_net_address: " << local_net_address << endl;
            
            local_socket_address = node.getChildNode("local_socket_address").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane local_socket_address: " << local_socket_address << endl;
            
            remote_net_address = node.getChildNode("remote_net_address").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane remote_net_address: " << remote_net_address << endl;
            
            remote_socket_address = node.getChildNode("remote_socket_address").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane remote_socket_address: " << remote_socket_address << endl;
        }
        
        cout << YELLOW << "[Done]" << RESET << " Nacitane udaje pre packet: " << protocol_type << endl;
        
        packets = node.getChildNode("packets").getText();
        cout << GREEN << "[OK]" << RESET << " Pocet packetov pre " << protocol_type << " je " << packets << endl;

        
        int count_packets = str_to_int(packets, 10);

        if (!protocol_type.compare(UDP)) {
            u_char* udp_packet = setup_udp_packet(70,
                    local_mac_address,
                    remote_mac_address,
                    protocol,
                    local_address,
                    remote_address,
                    protocol_type,
                    local_port,
                    remote_port,
                    service_name);

            for (int i = 0; i < count_packets; i++) {
                /* write packet to save file */
                pcap_dump((u_char *) pcap_dump_ip, header, udp_packet);
            }
            cout << YELLOW << "[Create]" << RESET << " Zapisujem UDP packet: " << endl << endl << endl;
        }
        if (!protocol_type.compare(TCP)) {
            u_char* tcp_packet = setup_tcp_packet(70,
                    local_mac_address,
                    remote_mac_address,
                    version,
                    local_address,
                    remote_address,
                    protocol_type,
                    local_port,
                    remote_port,
                    service_name);

            for (int i = 0; i < count_packets; i++) {
                /* write packet to save file */
                pcap_dump((u_char *) pcap_dump_ip, header, tcp_packet);
            }
            cout << YELLOW << "[Create]" << RESET << " Zapisujem TCP packet: " << endl << endl << endl;
        }
        if (!protocol_type.compare(PEP)) {
            u_char* ipx_packet = setup_ipx_packet(70,
                    local_mac_address,
                    remote_mac_address,
                    local_net_address,
                    remote_net_address,
                    local_socket_address,
                    remote_socket_address);

            for (int i = 0; i < count_packets; i++) {
                /* write packet to save file */
                pcap_dump((u_char *) pcap_dump_ip, header, ipx_packet);
            }
            cout << YELLOW << "[Create]" << RESET << " Zapisujem IPX PEP packet: " << endl << endl << endl;
        }

        index = "";
        frame_type = "";
        local_mac_address = "";
        remote_mac_address = "";
        protocol = "";
        version = "";
        local_address = "";
        remote_address = "";
        protocol_type = "";
        local_port = "";
        remote_port = "";
        service_name = "";
        service_name = "";
        packets = "";
        local_net_address = "";
        local_socket_address = "";
        remote_net_address = "";
        remote_socket_address = "";
    }

    pcap_close(pcap_dead_ip);
    pcap_dump_close(pcap_dump_ip);
    cout << BLUE << "[Done] Vsetky packety boli zapisane do: " << pcap_name  << RESET << endl;

    return 0;
}
