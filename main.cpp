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

#include <pcap.h>

using namespace std;

string const UDP("UDP");
string const TCP("TCP");
string const PEP("PEP");

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

//string parse_ip_address(string ip_adddress) {
//    auto it = std::remove_if(std::begin(ip_adddress), std::end(ip_adddress), [](char c) {
//        return (c == '.');
//    });
//    ip_adddress.erase(it, std::end(ip_adddress));
//
//    return ip_adddress;
//
//}

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

char * substr(string s, int x, int y) {
    char *ret = (char*) malloc(18);
    char * p = ret;
    char * q = &s[x];




    while (x < y) {
        *p++ = *q++;
        x++;
    }

    *p++ = '\0';

    return ret;
}

string dec_to_hexstr(string dec_str) {
    string result;

    long int decimalNumber = str_to_int(dec_str, 10);
    long int default_num = decimalNumber;
    long int quotient;
    int i = 1, j, temp;



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

    string local_mac_address_new = parse_mac_address(local_mac_address);
    string remote_mac_address_new = parse_mac_address(remote_mac_address);
    string local_net_address_new = parse_ipx_items(local_net_address);
    string remote_net_address_new = parse_ipx_items(remote_net_address);
    string local_socket_address_new = parse_ipx_items(local_socket_address);
    string remote_socket_address_new = parse_ipx_items(remote_socket_address);

    // 802.3 header

    // destination mac 00-03-ba-9a-15-63

    int j = 0;
    for (int i = 0; i <= 5; i++) {
        packet[i] = str_to_int(substr(remote_mac_address_new, j, j + 2)); // destination node 802.3
        packet[i + 24] = str_to_int(substr(remote_mac_address_new, j, j + 2)); // destination node IPX
        j += 2;
    }

    // source mac 00-1d-60-45-59-07
    j = 0;
    for (int i = 6; i <= 11; i++) {
        packet[i] = str_to_int(substr(local_mac_address_new, j, j + 2)); // source node 802.3
        packet[i + 30] = str_to_int(substr(local_mac_address_new, j, j + 2)); // source node IPX
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
    j = 0;
    for (int i = 20; i <= 23; i++) {
        packet[i] = str_to_int(substr(remote_net_address_new, j, j + 2));
        j += 2;
    }

    // destination socket 04 53
    packet[30] = str_to_int(substr(remote_socket_address_new, 0, 2));
    packet[31] = str_to_int(substr(remote_socket_address_new, 2, 4));

    // source network 30 09 80 00
    j = 0;
    for (int i = 32; i <= 35; i++) {
        packet[i] = str_to_int(substr(local_net_address_new, j, j + 2));
        j += 2;
    }

    // source socket 04 53
    packet[42] = str_to_int(substr(local_socket_address_new, 0, 2));
    packet[43] = str_to_int(substr(local_socket_address_new, 2, 4));

    for (int i = 44; i <= 60; i++) {
        packet[i] = 0x00;
    }


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

    //char* tmp = parse_mac_address("00-21-85-11-29-1b");
    //packet = parse_mac_address("00-21-85-11-29-1b");
    string local_mac_address_new = parse_mac_address(local_mac_address);
    string remote_mac_address_new = parse_mac_address(remote_mac_address);

    // mac destination address to 00-00-00-00-00-00
    //    packet[0] = str_to_int(substr(remote_mac_address_new, 0, 2));
    //    packet[1] = str_to_int(substr(remote_mac_address_new, 2, 4));
    //    packet[2] = str_to_int(substr(remote_mac_address_new, 4, 6));
    //    packet[3] = str_to_int(substr(remote_mac_address_new, 6, 8));
    //    packet[4] = str_to_int(substr(remote_mac_address_new, 8, 10));
    //    packet[5] = str_to_int(substr(remote_mac_address_new, 10, 12));
    int j = 0;
    for (int i = 0; i <= 5; i++) {
        packet[i] = str_to_int(substr(remote_mac_address_new, j, j + 2));
        j += 2;
    }

    // set mac source address to 00-21-85-11-29-1b
    //    packet[6] = str_to_int(substr(local_mac_address_new, 0, 2));
    //    packet[7] = str_to_int(substr(local_mac_address_new, 2, 4));
    //    packet[8] = str_to_int(substr(local_mac_address_new, 4, 6));
    //    packet[9] = str_to_int(substr(local_mac_address_new, 6, 8));
    //    packet[10] = str_to_int(substr(local_mac_address_new, 8, 10));
    //    packet[11] = str_to_int(substr(local_mac_address_new, 10, 12));
    j = 0;
    for (int i = 6; i <= 11; i++) {
        packet[i] = str_to_int(substr(local_mac_address_new, j, j + 2));
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
    
    // UDP information
    // udp source port
    string local_port_new = dec_to_hexstr(local_port); // 44 5c
    packet[34] = str_to_int(substr(local_port_new, 0, 2)); // D8E6
    packet[35] = str_to_int(substr(local_port_new, 2, 4));



    string remote_port_new = dec_to_hexstr(remote_port);
    // udp destination port
    packet[36] = str_to_int(substr(remote_port_new, 0, 2)); // 35
    packet[37] = str_to_int(substr(remote_port_new, 2, 4));

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
    //	for (i = 12; i < 20; i += 2) {
    //		word = ((packet[i] << 8) & 0xff00) + (packet[i+1] & 0xff);
    //		sum += (uint32_t) word;
    //	}

    sum += 17 + 40 - 20;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    sum = ~sum;

    packet[40] = (sum & 0xff00) >> 8;
    packet[41] = sum & 0xff;

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

    //char* tmp = parse_mac_address("00-21-85-11-29-1b");
    //packet = parse_mac_address("00-21-85-11-29-1b");
    string local_mac_address_new = parse_mac_address(local_mac_address);
    string remote_mac_address_new = parse_mac_address(remote_mac_address);

    // mac destination address to 00-00-00-00-00-00
    //    packet[0] = str_to_int(substr(remote_mac_address_new, 0, 2));
    //    packet[1] = str_to_int(substr(remote_mac_address_new, 2, 4));
    //    packet[2] = str_to_int(substr(remote_mac_address_new, 4, 6));
    //    packet[3] = str_to_int(substr(remote_mac_address_new, 6, 8));
    //    packet[4] = str_to_int(substr(remote_mac_address_new, 8, 10));
    //    packet[5] = str_to_int(substr(remote_mac_address_new, 10, 12));
    int j = 0;
    for (int i = 0; i <= 5; i++) {
        packet[i] = str_to_int(substr(remote_mac_address_new, j, j + 2));
        j += 2;
    }

    // set mac source address to 00-21-85-11-29-1b
    //    packet[6] = str_to_int(substr(local_mac_address_new, 0, 2));
    //    packet[7] = str_to_int(substr(local_mac_address_new, 2, 4));
    //    packet[8] = str_to_int(substr(local_mac_address_new, 4, 6));
    //    packet[9] = str_to_int(substr(local_mac_address_new, 6, 8));
    //    packet[10] = str_to_int(substr(local_mac_address_new, 8, 10));
    //    packet[11] = str_to_int(substr(local_mac_address_new, 10, 12));
    j = 0;
    for (int i = 6; i <= 11; i++) {
        packet[i] = str_to_int(substr(local_mac_address_new, j, j + 2));
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
    packet[18] = 0x3a;
    packet[19] = 0x50;

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
    
    // TCP information
    // TCP source port
    string local_port_new = dec_to_hexstr(local_port);
    cout << local_port << endl;
    cout << local_port_new << endl;
    packet[34] = str_to_int(substr(local_port_new, 0, 2));
    packet[35] = str_to_int(substr(local_port_new, 2, 4));

    // TCP destination port
    string remote_port_new = dec_to_hexstr(remote_port);
    packet[36] = str_to_int(substr(remote_port_new, 0, 2));
    packet[37] = str_to_int(substr(remote_port_new, 2, 4));

    // TCP sequence number: 0 (relative) example: 0x1626d405
    packet[38] = 0x16;
    packet[39] = 0x26;
    packet[40] = 0xd4;
    packet[41] = 0x05;


    // acknowledgment number : 1 example: 0x59042021
    packet[42] = 0x59;
    packet[43] = 0x04;
    packet[44] = 0x20;
    packet[45] = 0x21;

    // tcp header lenght
    packet[46] = 0x50; // 20 bytes

    // flags 0x01f
    packet[47] = 0x1f; // flags

    // window size
    packet[48] = 0x01; // example number
    packet[49] = 0x00;

    // checksum
    packet[50] = 0x00;
    packet[51] = 0x00;

    // neviem urgent pointer
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
    //	for (i = 12; i < 20; i += 2) {
    //		word = ((packet[i] << 8) & 0xff00) + (packet[i+1] & 0xff);
    //		sum += (uint32_t) word;
    //	}

    sum += 6 + 40 - 20;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    sum = ~sum;

    packet[50] = (sum & 0xff00) >> 8;
    packet[51] = sum & 0xff;

    return packet;
}

string set_broadcast_mac_address() {
    return "ff-ff-ff-ff-ff-ff";
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

    //ofstream pcap_file_new;
    char file_name[] = "packet.pcap";

    pcap_t *pcap_dead_ip;
    pcap_dumper_t *pcap_dump_ip;

    pcap_dead_ip = pcap_open_dead(DLT_EN10MB, 65535);

    // create the output file
    pcap_dump_ip = pcap_dump_open(pcap_dead_ip, file_name);

    timeval *ts = (timeval*) malloc(sizeof (timeval));
    ts->tv_sec = time(NULL);
    ts->tv_usec = 0;

    //creation of header
    pcap_pkthdr *header = (pcap_pkthdr*) malloc(sizeof (pcap_pkthdr));
    header->caplen = 60;
    header->len = 60;
    header->ts = *ts;

    // this open and parse the XML file:
    XMLNode xMainNode = XMLNode::openFileHelper("packets.xml", "packets_summary");

    int count_items = xMainNode.nChildNode();

    for (int i = 0; i < count_items; i++) {
        XMLNode node = xMainNode.getChildNode(i);

        protocol_type = node.getChildNode("protocol_type").getText();
        index = node.getChildNode("protocol").getText();
        local_mac_address = node.getChildNode("local_mac_address").getText();
        if (node.getChildNode("remote_mac_address").getText() != NULL) {
            remote_mac_address = node.getChildNode("remote_mac_address").getText();
        } else {
            remote_mac_address = set_broadcast_mac_address();
        }
        protocol = node.getChildNode("protocol").getText();
        frame_type = node.getChildNode("frame_type").getText();

        if (!protocol_type.compare(UDP) || !protocol_type.compare(TCP)) {

            version = node.getChildNode("version").getText();
            local_address = node.getChildNode("local_address").getText();
            remote_address = node.getChildNode("remote_address").getText();

            local_port = node.getChildNode("local_port").getText();
            remote_port = node.getChildNode("remote_port").getText();
            if (node.getChildNode("service_name").getText() != NULL) {
                service_name = node.getChildNode("service_name").getText();
            } else {
                service_name = "";
            }

        } else if (!protocol_type.compare(PEP)) {
            local_net_address = node.getChildNode("local_net_address").getText();
            local_socket_address = node.getChildNode("local_socket_address").getText();
            remote_net_address = node.getChildNode("remote_net_address").getText();
            remote_socket_address = node.getChildNode("remote_socket_address").getText();
        }


        packets = node.getChildNode("packets").getText();

        int count_packets = str_to_int(packets, 10);

        if (!protocol_type.compare(UDP)) {
            cout << "Vytvaram UDP packet" << endl;
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
                /*
                 * Create fake IP header and put UDP header
                 * and payload in place
                 */

                /* write packet to save file */
                pcap_dump((u_char *) pcap_dump_ip, header, udp_packet);
            }
        }
        if (!protocol_type.compare(TCP)) {
            cout << "Vytvaram TCP packet" << endl;
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
                /*
                 * Create fake IP header and put UDP header
                 * and payload in place
                 */

                /* write packet to save file */
                pcap_dump((u_char *) pcap_dump_ip, header, tcp_packet);
            }
        }
        if (!protocol_type.compare(PEP)) {
            cout << "Vytvaram IPX packet" << endl;
            u_char* ipx_packet = setup_ipx_packet(70,
                    local_mac_address,
                    remote_mac_address,
                    local_net_address,
                    remote_net_address,
                    local_socket_address,
                    remote_socket_address);

            for (int i = 0; i < count_packets; i++) {
                /*
                 * Create fake IP header and put UDP header
                 * and payload in place
                 */

                /* write packet to save file */
                pcap_dump((u_char *) pcap_dump_ip, header, ipx_packet);
            }
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

    return 0;
}
