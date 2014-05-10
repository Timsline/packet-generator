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
#include <array>
#include <vector>

using namespace std;

// setup
int const IPv4(0x45);
string const UDP("UDP");
string const TCP("TCP");
string const PEP("PEP");

// colors
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

u_char* setup_ike_packet(int size_of_packet,
        string local_mac_address,
        string remote_mac_address,
        string version_ike,
        string exchange_type,
        string local_address,
        string remote_address,
        string local_port,
        string remote_port) {
    u_char* packet;
    packet = (u_char*) malloc(size_of_packet);


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
    packet[16] = 0x01;
    packet[17] = 0x10; // 272 bytes

    // identification
    packet[18] = 0x00;
    packet[19] = 0x01;

    // flags
    packet[20] = 0x00;

    // fragment offset
    packet[21] = 0x00;

    // Time To Live - TTL  64
    packet[22] = 0x40;

    // protocol UDP - IKE je pri UDP
    packet[23] = 0x11;

    // IP header checksum
    packet[24] = 0x00;
    packet[25] = 0x00;

    // IP source address
    u_char* ipcko_local = parse_ip_addr("127.0.0.1");

    for (int i = 26; i <= 29; i++) {
        packet[i] = ipcko_local[i - 26];
    }

    // IP destination address
    u_char* ipcko_remote = parse_ip_addr("127.0.0.1");

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
    packet[39] = 0xfc; // 252 bytes

    // check sum
    packet[40] = 0x00;
    packet[41] = 0x00;


    // start of IKE (ISAKMP)

    //    // initiator cookie
    //    packet[42] = 0xdd;
    //    packet[43] = 0xe8;
    //    packet[44] = 0x90;
    //    packet[45] = 0xdb;
    //    packet[46] = 0x1f;
    //    packet[47] = 0x62;
    //    packet[48] = 0xef;
    //    packet[49] = 0x70;
    //
    //    // responder cookie
    //    for (int i = 0; i < 8; i++) {
    //        packet[i + 50] = 0x00;
    //    }
    //
    //    // next payload
    //    packet[58] = 0x21; // security association dec 33
    //
    //    // version
    //    packet[59] = 0x20;
    //
    //    // exchange type
    //    packet[60] = 0x22; // IKE_SA_INIT dec 34
    //
    //    // flags
    //    packet[61] = 0x08;
    //
    //    // message ID
    //    for (int i = 0; i < 4; i++) {
    //        packet[i + 62] = 0x00;
    //    }
    //
    //    // length 244
    //    packet[66] = 0x00;
    //    packet[67] = 0x00;
    //    packet[68] = 0x00;
    //    packet[69] = 0xf4;
    //
    //    // type payload: security association
    //
    //    // next payload
    //    packet[70] = 0x22; // key exchange dec 34
    //
    //    // critical bit
    //    packet[71] = 0x00;
    //
    //    // payload length 44
    //    packet[72] = 0x00;
    //    packet[73] = 0x2c;
    //
    //    packet[74] = 0x00;
    //
    //    // type payload: proposal (2) #1
    //
    //    // next payload: NONE / No next payload
    //    packet[75] = 0x00;
    //
    //    // critical bit
    //    packet[76] = 0x00;
    //
    //    // payload length 40
    //    packet[77] = 0x00;
    //    packet[78] = 0x28;
    //
    //    // proposal number 1
    //    packet[79] = 0x01;
    //
    //    // protocol ID: IKE 1
    //    packet[80] = 0x01;
    //
    //    // SPI size 0
    //    packet[81] = 0x00;
    //
    //    // proposal transforms
    //    packet[82] = 0x04;
    //
    //    // type payload: transform
    //
    //    // next payload: transform
    //    packet[83] = 0x03;
    //
    //    // critical bit
    //    packet[84] = 0x00;
    //
    //    // payload length
    //    packet[85] = 0x00;
    //    packet[86] = 0x08;
    //
    //    // transform type: encryption algorithm (ENCR)
    //    packet[87] = 0x01;
    //
    //    packet[88] = 0x00;
    //
    //    // transform ID: (ENCR) ENCR_3DES
    //    packet[89] = 0x00;
    //    packet[90] = 0x03;
    //
    //    // type payload transform
    //
    //    // next payload: transform
    //    packet[91] = 0x03;
    //
    //    // critical bit
    //    packet[92] = 0x00;
    //
    //    // payload length
    //    packet[93] = 0x00;
    //    packet[94] = 0x08;
    //
    //    // Transform Type: Pseudo-random Function (PRF) (2)
    //    packet[95] = 0x02;
    //
    //    packet[96] = 0x00;
    //
    //    // Transform ID (PRF): PRF_HMAC_MD5 (1)
    //    packet[97] = 0x00;
    //    packet[98] = 0x01;
    //    
    //        // next payload: transform
    //    packet[99] = 0x03;
    //
    //    // critical bit
    //    packet[100] = 0x00;
    //
    //    // payload length
    //    packet[101] = 0x00;
    //    packet[102] = 0x08;
    //
    //    // Transform Type: Integrity Algorithm (INTEG) (3)
    //    packet[103] = 0x03;
    //
    //    packet[104] = 0x00;
    //
    //    // Transform ID (INTEG): AUTH_HMAC_MD5_96 (1)
    //    packet[105] = 0x00;
    //    packet[106] = 0x01;
    //    
    //    
    //    packet[107] = 0x00;
    //    packet[108] = 0x00;
    //    packet[109] = 0x00;
    //    
    //    packet[107] = 0x08;
    //    packet[108] = 0x04;
    //    packet[109] = 0x00;
    //    packet[110] = 0x00;
    //    packet[111] = 0x02;
    //    
    //    packet[112] = 0x28;
    //    packet[113] = 0x00;
    //    packet[114] = 0x00;
    //    packet[115] = 0x88;
    //    packet[116] = 0x00;
    //    packet[117] = 0x02;
    //    
    //    for 

    //    packet[0] = 0x00;
    //packet[1] = 0x01;
    //packet[2] = 0x01;
    //packet[3] = 0x00;
    //packet[4] = 0x00;
    //packet[5] = 0x02;
    //packet[6] = 0x00;
    //packet[7] = 0x01;
    //packet[8] = 0x01;
    //packet[9] = 0x00;
    //packet[10] = 0x00;
    //packet[11] = 0x01;
    //packet[12] = 0x08;
    //packet[13] = 0x00;
    //packet[14] = 0x45;
    //packet[15] = 0x00;
    //packet[16] = 0x01;
    //packet[17] = 0x10;
    //packet[18] = 0x00;
    //packet[19] = 0x01;
    //packet[20] = 0x00;
    //packet[21] = 0x00;
    //packet[22] = 0x40;
    //packet[23] = 0x11;
    //packet[24] = 0x7b;
    //packet[25] = 0xda;
    //packet[26] = 0x7f;
    //packet[27] = 0x00;
    //packet[28] = 0x00;
    //packet[29] = 0x01;
    //packet[30] = 0x7f;
    //packet[31] = 0x00;
    //packet[32] = 0x00;
    //packet[33] = 0x01;
    //packet[34] = 0x01;
    //packet[35] = 0xf4;
    //packet[36] = 0x01;
    //packet[37] = 0xf4;
    //packet[38] = 0x00;
    //packet[39] = 0xfc;
    //packet[40] = 0x3d;
    //packet[41] = 0x64;
    packet[42] = 0xdd;
    packet[43] = 0xe8;
    packet[44] = 0x90;
    packet[45] = 0xdb;
    packet[46] = 0x1f;
    packet[47] = 0x62;
    packet[48] = 0xef;
    packet[49] = 0x70;
    packet[50] = 0x00;
    packet[51] = 0x00;
    packet[52] = 0x00;
    packet[53] = 0x00;
    packet[54] = 0x00;
    packet[55] = 0x00;
    packet[56] = 0x00;
    packet[57] = 0x00;
    packet[58] = 0x21;

    // IKE version 20 - 2 major 0 minor
    packet[59] = str_to_int(version_ike);

    // exchange type
    packet[60] = str_to_int(dec_to_hexstr(exchange_type));


    packet[61] = 0x08;
    packet[62] = 0x00;
    packet[63] = 0x00;
    packet[64] = 0x00;
    packet[65] = 0x00;
    packet[66] = 0x00;
    packet[67] = 0x00;
    packet[68] = 0x00;
    packet[69] = 0xf4;
    //packet[70] = 0x22;
    //packet[71] = 0x00;
    //packet[72] = 0x00;
    //packet[73] = 0x2c;
    //packet[74] = 0x00;
    //packet[75] = 0x00;
    //packet[76] = 0x00;
    //packet[77] = 0x28;
    //packet[78] = 0x01;
    //packet[79] = 0x01;
    //packet[80] = 0x00;
    //packet[81] = 0x04;
    //packet[82] = 0x03;
    //packet[83] = 0x00;
    //packet[84] = 0x00;
    //packet[85] = 0x08;
    //packet[86] = 0x01;
    //packet[87] = 0x00;
    //packet[88] = 0x00;
    //packet[89] = 0x03;
    //packet[90] = 0x03;
    //packet[91] = 0x00;
    //packet[92] = 0x00;
    //packet[93] = 0x08;
    //packet[94] = 0x02;
    //packet[95] = 0x00;
    //packet[96] = 0x00;
    //packet[97] = 0x01;
    //packet[98] = 0x03;
    //packet[99] = 0x00;
    //packet[100] = 0x00;
    //packet[101] = 0x08;
    //packet[102] = 0x03;
    //packet[103] = 0x00;
    //packet[104] = 0x00;
    //packet[105] = 0x01;
    //packet[106] = 0x00;
    //packet[107] = 0x00;
    //packet[108] = 0x00;
    //packet[109] = 0x08;
    //packet[110] = 0x04;
    //packet[111] = 0x00;
    //packet[112] = 0x00;
    //packet[113] = 0x02;
    //packet[114] = 0x28;
    //packet[115] = 0x00;
    //packet[116] = 0x00;
    //packet[117] = 0x88;
    //packet[118] = 0x00;
    //packet[119] = 0x02;
    //packet[120] = 0x00;
    //packet[121] = 0x00;
    //packet[122] = 0x00;
    //packet[123] = 0x00;
    //packet[124] = 0x00;
    //packet[125] = 0x00;
    //packet[126] = 0x00;
    //packet[127] = 0x00;
    //packet[128] = 0x00;
    //packet[129] = 0x00;
    //packet[130] = 0x00;
    //packet[131] = 0x00;
    //packet[132] = 0x00;
    //packet[133] = 0x00;
    //packet[134] = 0x00;
    //packet[135] = 0x00;
    //packet[136] = 0x00;
    //packet[137] = 0x00;
    //packet[138] = 0x00;
    //packet[139] = 0x00;
    //packet[140] = 0x00;
    //packet[141] = 0x00;
    //packet[142] = 0x00;
    //packet[143] = 0x00;
    //packet[144] = 0x00;
    //packet[145] = 0x00;
    //packet[146] = 0x00;
    //packet[147] = 0x00;
    //packet[148] = 0x00;
    //packet[149] = 0x00;
    //packet[150] = 0x00;
    //packet[151] = 0x00;
    //packet[152] = 0x00;
    //packet[153] = 0x00;
    //packet[154] = 0x00;
    //packet[155] = 0x00;
    //packet[156] = 0x00;
    //packet[157] = 0x00;
    //packet[158] = 0x00;
    //packet[159] = 0x00;
    //packet[160] = 0x00;
    //packet[161] = 0x00;
    //packet[162] = 0x00;
    //packet[163] = 0x00;
    //packet[164] = 0x00;
    //packet[165] = 0x00;
    //packet[166] = 0x00;
    //packet[167] = 0x00;
    //packet[168] = 0x00;
    //packet[169] = 0x00;
    //packet[170] = 0x00;
    //packet[171] = 0x00;
    //packet[172] = 0x00;
    //packet[173] = 0x00;
    //packet[174] = 0x00;
    //packet[175] = 0x00;
    //packet[176] = 0x00;
    //packet[177] = 0x00;
    //packet[178] = 0x00;
    //packet[179] = 0x00;
    //packet[180] = 0x00;
    //packet[181] = 0x00;
    //packet[182] = 0x00;
    //packet[183] = 0x00;
    //packet[184] = 0x00;
    //packet[185] = 0x00;
    //packet[186] = 0x00;
    //packet[187] = 0x00;
    //packet[188] = 0x00;
    //packet[189] = 0x00;
    //packet[190] = 0x00;
    //packet[191] = 0x00;
    //packet[192] = 0x00;
    //packet[193] = 0x00;
    //packet[194] = 0x00;
    //packet[195] = 0x00;
    //packet[196] = 0x00;
    //packet[197] = 0x00;
    //packet[198] = 0x00;
    //packet[199] = 0x00;
    //packet[200] = 0x00;
    //packet[201] = 0x00;
    //packet[202] = 0x00;
    //packet[203] = 0x00;
    //packet[204] = 0x00;
    //packet[205] = 0x00;
    //packet[206] = 0x00;
    //packet[207] = 0x00;
    //packet[208] = 0x00;
    //packet[209] = 0x00;
    //packet[210] = 0x00;
    //packet[211] = 0x00;
    //packet[212] = 0x00;
    //packet[213] = 0x00;
    //packet[214] = 0x00;
    //packet[215] = 0x00;
    //packet[216] = 0x00;
    //packet[217] = 0x00;
    //packet[218] = 0x00;
    //packet[219] = 0x00;
    //packet[220] = 0x00;
    //packet[221] = 0x00;
    //packet[222] = 0x00;
    //packet[223] = 0x00;
    //packet[224] = 0x00;
    //packet[225] = 0x00;
    //packet[226] = 0x00;
    //packet[227] = 0x00;
    //packet[228] = 0x00;
    //packet[229] = 0x00;
    //packet[230] = 0x00;
    //packet[231] = 0x00;
    //packet[232] = 0x00;
    //packet[233] = 0x00;
    //packet[234] = 0x00;
    //packet[235] = 0x00;
    //packet[236] = 0x00;
    //packet[237] = 0x00;
    //packet[238] = 0x00;
    //packet[239] = 0x00;
    //packet[240] = 0x00;
    //packet[241] = 0x00;
    //packet[242] = 0x00;
    //packet[243] = 0x00;
    //packet[244] = 0x00;
    //packet[245] = 0x00;
    //packet[246] = 0x96;
    //packet[247] = 0x94;
    //packet[248] = 0x96;
    //packet[249] = 0xca;
    //packet[250] = 0x00;
    //packet[251] = 0x00;
    //packet[252] = 0x00;
    //packet[253] = 0x24;
    //packet[254] = 0x9f;
    //packet[255] = 0x5f;
    //packet[256] = 0x16;
    //packet[257] = 0x41;
    //packet[258] = 0xc0;
    //packet[259] = 0x68;
    //packet[260] = 0x64;
    //packet[261] = 0x14;
    //packet[262] = 0x95;
    //packet[263] = 0x57;
    //packet[264] = 0x9a;
    //packet[265] = 0xdf;
    //packet[266] = 0xb0;
    //packet[267] = 0x0b;
    //packet[268] = 0x94;
    //packet[269] = 0x68;
    //packet[270] = 0xbb;
    //packet[271] = 0x49;
    //packet[272] = 0x2f;
    //packet[273] = 0xe3;
    //packet[274] = 0xcc;
    //packet[275] = 0xf9;
    //packet[276] = 0xef;
    //packet[277] = 0x31;
    //packet[278] = 0xc7;
    //packet[279] = 0xca;
    //packet[280] = 0x05;
    //packet[281] = 0x02;
    //packet[282] = 0x3b;
    //packet[283] = 0xd7;
    //packet[284] = 0x71;
    //packet[285] = 0xa0;


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

void create_packet_from_xml() {
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

    // ike
    string version_ike;
    string exchange_type;

    string pcap_name = "";
    string xml_name = "";

    cout << "Zadaj nazov pre pcap subor (\"packet.pcap\"): ";
    cin >> pcap_name;

    cout << "Zadaj cestu pre XML subor (\"packets.xml\"): ";
    cin >> xml_name;

    cout << GREEN << "[OK]" << RESET << " Vytvorene premenne pre XML" << endl;

    //char pcap_name[] = "packet.pcap";
    //char* xml_name;
    pcap_t *pcap_dead_ip;
    pcap_dumper_t *pcap_dump_ip;

    pcap_dead_ip = pcap_open_dead(DLT_EN10MB, 65535);

    // create the output file
    pcap_dump_ip = pcap_dump_open(pcap_dead_ip, pcap_name.c_str());

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
    XMLNode xMainNode = XMLNode::openFileHelper(xml_name.c_str(), "packets_summary");

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

        } else if (!protocol_type.compare("IKE")) {
            cout << YELLOW << "[UDP/TCP]" << RESET << " Specificke udaje pre UDP/TCP: " << endl;
            
            local_address = node.getChildNode("local_address").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane local_address: " << local_address << endl;

            remote_address = node.getChildNode("remote_address").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane remote_address: " << remote_address << endl;

            local_port = node.getChildNode("local_port").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane local_port: " << local_port << endl;

            remote_port = node.getChildNode("remote_port").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane remote_port: " << remote_port << endl;

            cout << YELLOW << "[IKE]" << RESET << " Specificke udaje pre (UDP) IKE: " << endl;

            version_ike = node.getChildNode("version_ike").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane version_ike: " << version_ike << endl;

            exchange_type = node.getChildNode("exchange_type").getText();
            cout << GREEN << "[OK]" << RESET << " Nacitane exchange_type: " << exchange_type << endl;
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
            cout << YELLOW << "[Create]" << RESET << " Zapisujem UDP packet..." << endl << endl << endl;
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
            cout << YELLOW << "[Create]" << RESET << " Zapisujem TCP packet..." << endl << endl << endl;
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
            cout << YELLOW << "[Create]" << RESET << " Zapisujem IPX PEP packet..." << endl << endl << endl;
        }

        if (!protocol_type.compare("IKE")) {
            u_char* ike_packet = setup_ike_packet(286,
                    local_mac_address,
                    remote_mac_address,
                    version_ike,
                    exchange_type,
                    local_address,
                    remote_address,
                    local_port,
                    remote_port);

            // 286
            timeval *ts_ike = (timeval*) malloc(sizeof (timeval));
            ts_ike->tv_sec = time(NULL);
            ts_ike->tv_usec = 0;

            //creation of header
            pcap_pkthdr *header_ike = (pcap_pkthdr*) malloc(sizeof (pcap_pkthdr));
            header_ike->caplen = 286;
            header_ike->len = 286;
            header_ike->ts = *ts;

            for (int i = 0; i < count_packets; i++) {
                /* write packet to save file */
                pcap_dump((u_char *) pcap_dump_ip, header_ike, ike_packet);
            }

            cout << YELLOW << "[Create]" << RESET << " Zapisujem IP UDP IKE packet..." << endl << endl << endl;
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
        
        exchange_type = "";
        version_ike = "";
    }



    pcap_close(pcap_dead_ip);
    pcap_dump_close(pcap_dump_ip);
    cout << BLUE << "[Done] Vsetky packety boli zapisane do: " << pcap_name << RESET << endl;

}

void read_packet_from_xml() {
    string local_mac_address = "";
    string remote_mac_address = "";
    string protocol = "";
    string local_address = "";
    string remote_address = "";
    string local_port = "";
    string remote_port = "";

    //ipx
    string local_net_address;
    string local_socket_address;
    string remote_net_address;
    string remote_socket_address;

    // change
    string local_mac_address_ch = "";
    string remote_mac_address_ch = "";
    string local_address_ch = "";
    string remote_address_ch = "";
    string local_port_ch = "";
    string remote_port_ch = "";
    //ipx
    string local_net_address_ch = "";
    string local_socket_address_ch = "";
    string remote_net_address_ch = "";
    string remote_socket_address_ch = "";

    string pcap_name = "";
    string pcap_name_new = "";
    string xml_name = "";

    cout << "Zadaj nazov pcap suboru pre otvorenie (\"packet.pcap\"): ";
    cin >> pcap_name;

    cout << "Zadaj nazov noveho pcap suboru (\"changed.pcap\"): ";
    cin >> pcap_name_new;

    cout << "Zadaj cestu pre XML subor (\"change.xml\"): ";
    cin >> xml_name;



    // read pcap file    
    pcap_t* opened_file;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *pcap_dead_ip;
    pcap_dumper_t *pcap_dump_ip;

    // pole stiahnutych pcap
    u_char array[100][70];

    const u_char* data;
    pcap_t* r_d;

    timeval *ts_h = (timeval*) malloc(sizeof (timeval));
    ts_h->tv_sec = time(NULL);
    ts_h->tv_usec = 0;

    //creation of header
    pcap_pkthdr *r_h = (pcap_pkthdr*) malloc(sizeof (pcap_pkthdr));
    r_h->caplen = 62;
    r_h->len = 62;
    r_h->ts = *ts_h;


    XMLNode xMainNode = XMLNode::openFileHelper(xml_name.c_str(), "configure_summary");

    cout << GREEN << "[OK]" << RESET << " Nacitany XML subor: " << xml_name << endl << endl;


    int count_items = xMainNode.nChildNode();


    // otvorenie suboru na citanie
    if ((opened_file = pcap_open_offline(pcap_name.c_str(), errbuf)) == NULL) {
        cout << "Subor sa nepodarilo otvorit.\n" << endl;
        cout << RED << "[OK]" << RESET << "Subor sa nepodarilo otvorit: " << pcap_name << endl;
        return;
    } else
        cout << GREEN << "[OK]" << RESET << "Subor sa podarilo otvorit: " << pcap_name << endl;

    int numberOfRows = 0;
    while (pcap_next_ex(opened_file, &r_h, &data) >= 0) {
        for (int i = 0; i < 70; i++) {
            array[numberOfRows][i] = data[i];
        }
        numberOfRows++;
    }

    for (int i = 0; i < count_items; i++) {
        XMLNode node = xMainNode.getChildNode(i);
        cout << YELLOW << "[Start]" << RESET << " Nacitavanie dat z XML" << endl;

        if (node.getChildNode("filter_parameters").getChildNode("protocol").getText() != NULL) {
            protocol = node.getChildNode("filter_parameters").getChildNode("protocol").getText();
            cout << "Filter parameter protocol: " << protocol << endl;
        }

        if (node.getChildNode("filter_parameters").getChildNode("local_mac_address").getText() != NULL) {
            local_mac_address = node.getChildNode("filter_parameters").getChildNode("local_mac_address").getText();
            cout << "Filter parameter local_mac_address: " << local_mac_address << endl;
        }

        if (node.getChildNode("filter_parameters").getChildNode("remote_mac_address").getText() != NULL) {
            remote_mac_address = node.getChildNode("filter_parameters").getChildNode("remote_mac_address").getText();
            cout << "Filter parameter remote_mac_address: " << remote_mac_address << endl;
        }

        if (node.getChildNode("filter_parameters").getChildNode("local_address").getText() != NULL) {
            local_address = node.getChildNode("filter_parameters").getChildNode("local_address").getText();
            cout << "Filter parameter local_address: " << local_address << endl;
        }

        if (node.getChildNode("filter_parameters").getChildNode("remote_address").getText() != NULL) {
            remote_address = node.getChildNode("filter_parameters").getChildNode("remote_address").getText();
            cout << "Filter parameter remote_address: " << remote_address << endl;
        }

        if (node.getChildNode("filter_parameters").getChildNode("local_port").getText() != NULL) {
            local_port = node.getChildNode("filter_parameters").getChildNode("local_port").getText();
            cout << "Filter parameter local_port: " << local_port << endl;
        }

        if (node.getChildNode("filter_parameters").getChildNode("remote_port").getText() != NULL) {
            remote_port = node.getChildNode("filter_parameters").getChildNode("remote_port").getText();
            cout << "Filter parameter remote_port: " << remote_port << endl;
        }

        // filter ipx
        if (node.getChildNode("filter_parameters").getChildNode("local_net_address").getText() != NULL) {
            local_net_address = node.getChildNode("filter_parameters").getChildNode("local_net_address").getText();
            cout << "Filter parameter local_net_address: " << local_net_address << endl;
        }

        if (node.getChildNode("filter_parameters").getChildNode("local_socket_address").getText() != NULL) {
            local_socket_address = node.getChildNode("filter_parameters").getChildNode("local_socket_address").getText();
            cout << "Filter parameter local_socket_address: " << local_socket_address << endl;
        }

        if (node.getChildNode("filter_parameters").getChildNode("remote_net_address").getText() != NULL) {
            remote_net_address = node.getChildNode("filter_parameters").getChildNode("remote_net_address").getText();
            cout << "Filter parameter remote_net_address: " << remote_net_address << endl;
        }

        if (node.getChildNode("filter_parameters").getChildNode("remote_socket_address").getText() != NULL) {
            remote_socket_address = node.getChildNode("filter_parameters").getChildNode("remote_socket_address").getText();
            cout << "Filter parameter remote_socket_address: " << remote_socket_address << endl;
        }

        // change parameters
        if (node.getChildNode("change_parameters").getChildNode("local_mac_address").getText() != NULL) {
            local_mac_address_ch = node.getChildNode("change_parameters").getChildNode("local_mac_address").getText();
            cout << "Change parameter local_mac_address: " << local_mac_address_ch << endl;
        }
        if (node.getChildNode("change_parameters").getChildNode("remote_mac_address").getText() != NULL) {
            remote_mac_address_ch = node.getChildNode("change_parameters").getChildNode("remote_mac_address").getText();
            cout << "Change parameter remote_mac_address: " << remote_mac_address_ch << endl;
        }

        if (node.getChildNode("change_parameters").getChildNode("local_address").getText() != NULL) {
            local_address_ch = node.getChildNode("change_parameters").getChildNode("local_address").getText();
            cout << "Change parameter local_address: " << local_address_ch << endl;
        }

        if (node.getChildNode("change_parameters").getChildNode("remote_address").getText() != NULL) {
            remote_address_ch = node.getChildNode("change_parameters").getChildNode("remote_address").getText();
            cout << "Change parameter remote_address: " << remote_address_ch << endl;
        }

        if (node.getChildNode("change_parameters").getChildNode("local_port").getText() != NULL) {
            local_port_ch = node.getChildNode("change_parameters").getChildNode("local_port").getText();
            cout << "Change parameter local_port: " << local_port_ch << endl;
        }

        if (node.getChildNode("change_parameters").getChildNode("remote_port").getText() != NULL) {
            remote_port_ch = node.getChildNode("change_parameters").getChildNode("remote_port").getText();
            cout << "Change parameter remote_port: " << remote_port_ch << endl;
        }

        // IPX change
        if (node.getChildNode("change_parameters").getChildNode("local_net_address").getText() != NULL) {
            local_net_address_ch = node.getChildNode("change_parameters").getChildNode("local_net_address").getText();
            cout << "Change parameter local_net_address: " << local_net_address_ch << endl;
        }

        if (node.getChildNode("change_parameters").getChildNode("local_socket_address").getText() != NULL) {
            local_socket_address_ch = node.getChildNode("change_parameters").getChildNode("local_socket_address").getText();
            cout << "Change parameter local_socket_address: " << local_socket_address_ch << endl;
        }

        if (node.getChildNode("change_parameters").getChildNode("remote_net_address").getText() != NULL) {
            remote_net_address_ch = node.getChildNode("change_parameters").getChildNode("remote_net_address").getText();
            cout << "Change parameter remote_net_address: " << remote_net_address_ch << endl;
        }

        if (node.getChildNode("change_parameters").getChildNode("remote_socket_address").getText() != NULL) {
            remote_socket_address_ch = node.getChildNode("change_parameters").getChildNode("remote_socket_address").getText();
            cout << "Change parameter remote_socket_address: " << remote_socket_address_ch << endl;
        }

        if (!protocol.compare("TCP")) {
            cout << "Upravujem TCP packet..." << endl;

            /*
             *  frame_type
             *  local_mac_address
             *  remote_mac_address
             *  protocol
             *  protocol_type
             *  local_address
             *  remote_address
             *  local_port
             *  remote_port
             */

            for (int r = 0; r < numberOfRows; r++) {
                // ak je to tcp
                if (array[r][23] == 0x06) {
                    if (local_address.length() != 0) {
                        u_char* la = parse_ip_addr(local_address);
                        if (!(array[r][26] == la[0] && array[r][27] == la[1] && array[r][28] == la[2] && array[r][29] == la[3])) {
                            continue;
                        }
                    }

                    if (remote_address.length() != 0) {
                        u_char* ra = parse_ip_addr(remote_address);
                        if (!(array[r][30] == ra[0] && array[r][31] == ra[1] && array[r][32] == ra[2] && array[r][33] == ra[3])) {
                            continue;
                        }
                    }

                    if (remote_port.length() != 0) {
                        string rp = dec_to_hexstr(remote_port);
                        if (!(array[r][36] == str_to_int(rp.substr(0, 2)) && array[r][37] == str_to_int(rp.substr(2, 2)))) {
                            continue;
                        }
                    }

                    if (local_port.length() != 0) {
                        string lp = dec_to_hexstr(local_port);
                        if (!(array[r][34] == str_to_int(lp.substr(0, 2)) && array[r][35] == str_to_int(lp.substr(2, 2)))) {
                            continue;
                        }
                    }

                    if (local_mac_address.length() != 0) {
                        string lmc = parse_mac_address(local_mac_address);
                        int j = 0;
                        for (int i = 6; i <= 11; i++) {
                            if (!(array[r][i] == str_to_int(lmc.substr(j, 2)))) {
                                continue;
                            }
                            j += 2;
                        }
                    }

                    if (remote_mac_address.length() != 0) {
                        string rmc = parse_mac_address(remote_mac_address);
                        int j = 0;
                        for (int i = 0; i <= 5; i++) {
                            if (!(array[r][i] == str_to_int(rmc.substr(j, 2)))) {
                                continue;
                            }
                            j += 2;
                        }
                    }

                    // change parameters
                    /*
                     * local_mac_address
                     * remote_mac_address
                     * local_address
                     * remote_address
                     * local_port
                     * remote_port
                     */
                    if (remote_port_ch != "") {
                        string rp = dec_to_hexstr(remote_port_ch);
                        array[r][36] = str_to_int(rp.substr(0, 2));
                        array[r][37] = str_to_int(rp.substr(2, 2));
                    }
                    if (local_port_ch != "") {
                        string lp = dec_to_hexstr(local_port_ch);
                        array[r][34] = str_to_int(lp.substr(0, 2));
                        array[r][35] = str_to_int(lp.substr(2, 2));
                    }

                    if (local_mac_address_ch != "") {
                        string lma = parse_mac_address(local_mac_address_ch);
                        int j = 0;
                        for (int i = 6; i <= 11; i++) {
                            array[r][i] = str_to_int(lma.substr(j, 2));
                            j += 2;
                        }
                    }

                    if (remote_mac_address_ch != "") {
                        string rma = parse_mac_address(remote_mac_address_ch);
                        int j = 0;
                        for (int i = 0; i <= 5; i++) {
                            array[r][i] = str_to_int(rma.substr(j, 2));
                            j += 2;
                        }
                    }

                    if (local_address_ch != "") {
                        u_char* la = parse_ip_addr(local_address_ch);
                        for (int i = 26; i <= 29; i++) {
                            array[r][i] = la[i - 26];
                        }
                    }

                    if (remote_address_ch != "") {
                        u_char* ra = parse_ip_addr(remote_address_ch);
                        for (int i = 30; i <= 33; i++) {
                            array[r][i] = ra[i - 30];
                        }
                    }
                }
            }

        } else if (!protocol.compare("UDP")) {
            cout << "Upravujem UDP packet..." << endl;

            for (int r = 0; r < numberOfRows; r++) {
                // ak je to udp
                if (array[r][23] == 0x11) {

                    if (local_address.length() != 0) {
                        u_char* la = parse_ip_addr(local_address);
                        if (!(array[r][26] == la[0] && array[r][27] == la[1] && array[r][28] == la[2] && array[r][29] == la[3])) {
                            continue;
                        }
                    }

                    if (remote_address.length() != 0) {
                        u_char* ra = parse_ip_addr(remote_address);
                        if (!(array[r][30] == ra[0] && array[r][31] == ra[1] && array[r][32] == ra[2] && array[r][33] == ra[3])) {
                            continue;
                        }
                    }

                    if (remote_port.length() != 0) {
                        string rp = dec_to_hexstr(remote_port);
                        if (!(array[r][36] == str_to_int(rp.substr(0, 2)) && array[r][37] == str_to_int(rp.substr(2, 2)))) {
                            continue;
                        }
                    }

                    if (local_port.length() != 0) {
                        string lp = dec_to_hexstr(local_port);
                        if (!(array[r][34] == str_to_int(lp.substr(0, 2)) && array[r][35] == str_to_int(lp.substr(2, 2)))) {
                            continue;
                        }
                    }

                    if (local_mac_address.length() != 0) {
                        string lmc = parse_mac_address(local_mac_address);
                        int j = 0;
                        for (int i = 6; i <= 11; i++) {
                            if (!(array[r][i] == str_to_int(lmc.substr(j, 2)))) {
                                continue;
                            }
                            j += 2;
                        }
                    }

                    if (remote_mac_address.length() != 0) {
                        string rmc = parse_mac_address(remote_mac_address);
                        int j = 0;
                        for (int i = 0; i <= 5; i++) {
                            if (!(array[r][i] == str_to_int(rmc.substr(j, 2)))) {
                                continue;
                            }
                            j += 2;
                        }
                    }

                    // change parameters
                    /*
                     * local_mac_address
                     * remote_mac_address
                     * local_address
                     * remote_address
                     * local_port
                     * remote_port
                     */
                    if (remote_port_ch != "") {
                        string rp = dec_to_hexstr(remote_port_ch);
                        array[r][36] = str_to_int(rp.substr(0, 2));
                        array[r][37] = str_to_int(rp.substr(2, 2));
                    }
                    if (local_port_ch != "") {
                        string lp = dec_to_hexstr(local_port_ch);
                        array[r][34] = str_to_int(lp.substr(0, 2));
                        array[r][35] = str_to_int(lp.substr(2, 2));
                    }

                    if (local_mac_address_ch != "") {
                        string lma = parse_mac_address(local_mac_address_ch);
                        int j = 0;
                        for (int i = 6; i <= 11; i++) {
                            array[r][i] = str_to_int(lma.substr(j, 2));
                            j += 2;
                        }
                    }

                    if (remote_mac_address_ch != "") {
                        string rma = parse_mac_address(remote_mac_address_ch);
                        int j = 0;
                        for (int i = 0; i <= 5; i++) {
                            array[r][i] = str_to_int(rma.substr(j, 2));
                            j += 2;
                        }
                    }

                    if (local_address_ch != "") {
                        u_char* la = parse_ip_addr(local_address_ch);
                        for (int i = 26; i <= 29; i++) {
                            array[r][i] = la[i - 26];
                        }
                    }

                    if (remote_address_ch != "") {
                        u_char* ra = parse_ip_addr(remote_address_ch);
                        for (int i = 30; i <= 33; i++) {
                            array[r][i] = ra[i - 30];
                        }
                    }
                }
            }
        } else if (!protocol.compare("IPX")) {
            cout << "Upravujem IPX packet..." << endl;

            /*
                local_mac_address
                remote_mac_address
                local_net_address
                local_socket_address
                remote_net_address
                remote_socket_address
             */

            for (int r = 0; r < numberOfRows; r++) {
                // ak je to udp
                if (array[r][14] == 0xFF && array[r][15] == 0xFF) {
                    // filter parameters
                    if (local_mac_address.length() != 0) {
                        string lmc = parse_mac_address(local_mac_address);
                        int j = 0;
                        for (int i = 6; i <= 11; i++) {
                            if (!(array[r][i] == str_to_int(lmc.substr(j, 2)))) {
                                continue;
                            }
                            j += 2;
                        }
                    }

                    if (remote_mac_address.length() != 0) {
                        string rmc = parse_mac_address(remote_mac_address);
                        int j = 0;
                        for (int i = 0; i <= 5; i++) {
                            if (!(array[r][i] == str_to_int(rmc.substr(j, 2)))) {
                                continue;
                            }
                            j += 2;
                        }
                    }

                    if (local_net_address.length() != 0) {
                        string lna = parse_ipx_items(local_net_address);
                        int j = 0;
                        for (int i = 32; i <= 35; i++) {
                            if (!(array[r][i] == str_to_int(lna.substr(j, 2)))) {
                                continue;
                            }
                            j += 2;
                        }
                    }

                    if (remote_net_address.length() != 0) {
                        string rna = parse_ipx_items(remote_net_address);
                        int j = 0;
                        for (int i = 20; i <= 23; i++) {
                            if (!(array[r][i] == str_to_int(rna.substr(j, 2)))) {
                                continue;
                            }
                            j += 2;
                        }
                    }

                    if (remote_socket_address.length() != 0) {
                        string rsa = parse_ipx_items(remote_socket_address);
                        int j = 0;
                        for (int i = 30; i <= 31; i++) {
                            if (!(array[r][i] == str_to_int(rsa.substr(j, 2)))) {
                                continue;
                            }
                            j += 2;
                        }
                    }

                    if (local_socket_address.length() != 0) {
                        string lsa = parse_ipx_items(local_socket_address);
                        int j = 0;
                        for (int i = 42; i <= 43; i++) {
                            if (!(array[r][i] == str_to_int(lsa.substr(j, 2)))) {
                                continue;
                            }
                            j += 2;
                        }
                    }

                    // change
                    if (local_mac_address_ch != "") {
                        string lma = parse_mac_address(local_mac_address_ch);
                        int j = 0;
                        for (int i = 6; i <= 11; i++) {
                            array[r][i] = str_to_int(lma.substr(j, 2));
                            j += 2;
                        }
                    }

                    if (remote_mac_address_ch != "") {
                        string rma = parse_mac_address(remote_mac_address_ch);
                        int j = 0;
                        for (int i = 0; i <= 5; i++) {
                            array[r][i] = str_to_int(rma.substr(j, 2));
                            j += 2;
                        }
                    }

                    if (local_net_address_ch != "") {
                        string lna = parse_ipx_items(local_net_address_ch);
                        int j = 0;
                        for (int i = 32; i <= 35; i++) {
                            array[r][i] = str_to_int(lna.substr(j, 2));
                            j += 2;
                        }
                    }

                    if (remote_net_address_ch != "") {
                        string rna = parse_ipx_items(remote_net_address_ch);
                        int j = 0;
                        for (int i = 20; i <= 23; i++) {
                            array[r][i] = str_to_int(rna.substr(j, 2));
                            j += 2;
                        }
                    }

                    if (remote_socket_address_ch != "") {
                        string rsa = parse_ipx_items(remote_socket_address_ch);
                        int j = 0;
                        for (int i = 30; i <= 31; i++) {
                            array[r][i] = str_to_int(rsa.substr(j, 2));
                            j += 2;
                        }
                    }

                    if (local_socket_address_ch != "") {
                        string lsa = parse_ipx_items(local_socket_address_ch);
                        int j = 0;
                        for (int i = 42; i <= 43; i++) {
                            array[r][i] = str_to_int(lsa.substr(j, 2));
                            j += 2;
                        }
                    }
                }
            }
        }

        local_mac_address = "";
        remote_mac_address = "";
        protocol = "";
        local_address = "";
        remote_address = "";
        local_port = "";
        remote_port = "";

        local_mac_address_ch = "";
        remote_mac_address_ch = "";
        local_address_ch = "";
        remote_address_ch = "";
        local_port_ch = "";
        remote_port_ch = "";

        local_net_address = "";
        local_socket_address = "";
        remote_net_address = "";
        remote_socket_address = "";

        local_net_address_ch = "";
        local_socket_address_ch = "";
        remote_net_address_ch = "";
        remote_socket_address_ch = "";

    }

    // create new pcap
    pcap_dead_ip = pcap_open_dead(DLT_EN10MB, 65535);

    // create the output file
    pcap_dump_ip = pcap_dump_open(pcap_dead_ip, pcap_name_new.c_str());


    timeval *ts = (timeval*) malloc(sizeof (timeval));
    ts->tv_sec = time(NULL);
    ts->tv_usec = 0;

    //creation of header
    pcap_pkthdr *header = (pcap_pkthdr*) malloc(sizeof (pcap_pkthdr));
    header->caplen = 62;
    header->len = 62;
    header->ts = *ts;

    for (int i = 0; i < numberOfRows; i++) {
        /* write packet to save file */
        pcap_dump((u_char *) pcap_dump_ip, header, array[i]);
        // ma velkost array[20][70]
    }

    pcap_close(pcap_dead_ip);
    pcap_dump_close(pcap_dump_ip);
}

int main(int argc, char **argv) {
    // info o programe
    info_program();

    int choice = 0;

    do {
        cout << "\nMenu packet generatora:" << endl;
        cout << "1. Generovanie packetu." << endl;
        cout << "2. Zmena packetu." << endl;
        cout << "3. Clear obrazovky." << endl;
        cout << "4. Koniec programu." << endl << endl;

        cout << "Vyber volbu: ";
        cin >> choice;

        switch (choice) {
            case 1:
                create_packet_from_xml();
                break;
            case 2:
                read_packet_from_xml();
                break;
            case 3:
                system("clear");
                break;
            case 4:
                return 0;
        }

    } while (choice != 4);

    return 0;
}
