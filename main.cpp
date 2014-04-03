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

int str_to_int(string text) {
    return stoi(text, NULL, 16);
}

int str_to_int(string text, int base) {
    return stoi(text, NULL, base);
}

//00-00-00-00-00-00

string parse_mac_address(string mac_address) {
    auto it = std::remove_if(std::begin(mac_address), std::end(mac_address), [](char c) {
        return (c == '-');
    });
    mac_address.erase(it, std::end(mac_address));

    return mac_address;

}

string parse_ip_address(string ip_adddress) {
    auto it = std::remove_if(std::begin(ip_adddress), std::end(ip_adddress), [](char c) {
        return (c == '.');
    });
    ip_adddress.erase(it, std::end(ip_adddress));

    return ip_adddress;

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

char* create_udp_packet(int size_of_packet) {
    char* packet;
    packet = (char*) malloc((size_of_packet)*1);

    //char* tmp = parse_mac_address("00-21-85-11-29-1b");
    //packet = parse_mac_address("00-21-85-11-29-1b");
    string mac = parse_mac_address("00-21-85-11-29-1b");

    // mac destination address to 00-00-00-00-00-00
    packet[0] = 0;
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 0;
    packet[4] = 0;
    packet[5] = 0;

    // set mac source address to 00-21-85-11-29-1b
    //    packet[6] = str_to_int(substr(mac,0,2));
    //    packet[7] = str_to_int(substr(mac,2,4));
    //    packet[8] = str_to_int(substr(mac,4,6));
    //    packet[9] = str_to_int(substr(mac,6,8));
    //    packet[10] = str_to_int(substr(mac,8,10));
    //    packet[11] = str_to_int(substr(mac,10,12)); 


    int j = 0;
    for (int i = 6; i <= 11; i++) {
        packet[i] = str_to_int(substr(mac, j, j + 2));
        j += 2;
    }
    // set IP protocol 0x0800

    packet[12] = 0x08;
    packet[13] = 0x00;

    // IPv4 = 0x45
    packet[14] = 0x45;

    // ??
    packet[15] = 0x00;

    // length IP
    packet[16] = 0x00;
    packet[17] = 0x00;

    // identification
    packet[18] = 0x00;
    packet[19] = 0x00;

    // flags
    packet[20] = 0x00;


    packet[21] = 0x00;

    // Time To Live - TTL  128?
    packet[22] = 0x40;

    // protocol UDP
    packet[23] = str_to_int("17", 10);

    // UDP header checksum
    packet[24] = 0x00;
    packet[25] = 0x00;

    // IP source address 147.175.106.141
    packet[26] = str_to_int("147", 10);
    packet[27] = str_to_int("175", 10);
    packet[28] = str_to_int("106", 10);
    packet[29] = str_to_int("141", 10);

    // IP destination address
    packet[30] = str_to_int("255", 10);
    packet[31] = str_to_int("255", 10);
    packet[32] = str_to_int("255", 10);
    packet[33] = str_to_int("255", 10);

    // UDP information
    // udp source port
    packet[34] = str_to_int("44");
    packet[35] = str_to_int("5c");

    // udp destination port
    packet[36] = str_to_int("44");
    packet[37] = str_to_int("5c");

    // udp length
    packet[38] = 0x00;
    packet[39] = 0x14;

    // check sum
    packet[40] = 0x00;
    packet[41] = 0x00;


    // data 50:69:76:61:72:6e:69:6b:20:6a:65:20:68:6f:6d:6f:73:20:3a:44
    packet[42] = 0x50;
    packet[43] = 0x69;
    packet[44] = 0x76;
    packet[45] = 0x61;

    packet[46] = 0x72;
    packet[47] = 0x6e;
    packet[48] = 0x69;
    packet[49] = 0x6b;
    packet[50] = 0x20;
    packet[51] = 0x6a;
    packet[52] = 0x65;
    packet[53] = 0x20;

    packet[54] = 0x68;
    packet[55] = 0x6f;
    packet[56] = 0x6d;
    packet[57] = 0x6f;
    packet[58] = 0x73;
    packet[59] = 0x20;
    packet[60] = 0x3a;
    packet[61] = 0x44;

    return packet;
}

char* create_udp_packet2(int size_of_packet,
        string local_mac_address,
        string remote_mac_address,
        string version,
        string local_address,
        string remote_address,
        string protocol_type,
        string local_port,
        string remote_port,
        string service_name) {

    char* packet;
    packet = (char*) malloc((size_of_packet)*1);

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
    packet[14] = 0x45;

    // ??
    packet[15] = 0x00;

    // length IP
    packet[16] = 0x00;
    packet[17] = 0x00;

    // identification
    packet[18] = 0x00;
    packet[19] = 0x00;

    // flags
    packet[20] = 0x00;


    packet[21] = 0x00;

    // Time To Live - TTL  128?
    packet[22] = 0x40;

    // protocol UDP
    packet[23] = str_to_int("17", 10);

    // UDP header checksum
    packet[24] = 0x00;
    packet[25] = 0x00;

    // IP source address 147.175.106.141
    string local_address_new = parse_ip_address(local_address);
    if (local_address_new.length() == 12) {
        //cout << local_address_new << " .." << endl;
        int j = 0;
        for (int i = 26; i <= 29; i++) {
            packet[i] = str_to_int(substr(local_address_new, j, j + 3), 10);
            j += 3;
        }
    }

//    packet[26] = str_to_int("147", 10);
//    packet[27] = str_to_int("175", 10);
//    packet[28] = str_to_int("106", 10);
//    packet[29] = str_to_int("141", 10);

    // IP destination address
    packet[30] = str_to_int("255", 10);
    packet[31] = str_to_int("255", 10);
    packet[32] = str_to_int("255", 10);
    packet[33] = str_to_int("255", 10);

    // UDP information
    // udp source port
    packet[34] = str_to_int("44");
    packet[35] = str_to_int("5c");

    // udp destination port
    packet[36] = str_to_int("44");
    packet[37] = str_to_int("5c");

    // udp length
    packet[38] = 0x00;
    packet[39] = 0x14;

    // check sum
    packet[40] = 0x00;
    packet[41] = 0x00;


    // data 50:69:76:61:72:6e:69:6b:20:6a:65:20:68:6f:6d:6f:73:20:3a:44
    packet[42] = 0x50;
    packet[43] = 0x69;
    packet[44] = 0x76;
    packet[45] = 0x61;

    packet[46] = 0x72;
    packet[47] = 0x6e;
    packet[48] = 0x69;
    packet[49] = 0x6b;
    packet[50] = 0x20;
    packet[51] = 0x6a;
    packet[52] = 0x65;
    packet[53] = 0x20;

    packet[54] = 0x68;
    packet[55] = 0x6f;
    packet[56] = 0x6d;
    packet[57] = 0x6f;
    packet[58] = 0x73;
    packet[59] = 0x20;
    packet[60] = 0x3a;
    packet[61] = 0x44;

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

    //ofstream pcap_file_new;
    char file_name[] = "packet.pcap";




    pcap_t *cap_dead;
    pcap_dumper_t *cap_dumper;

    cap_dead = pcap_open_dead(DLT_EN10MB, 65535);

    // create the output file
    cap_dumper = pcap_dump_open(cap_dead, file_name);

    timeval *ts = (timeval*) malloc(sizeof (timeval));
    ts->tv_sec = time(NULL);
    ts->tv_usec = 0;

    //creation of header
    pcap_pkthdr *header = (pcap_pkthdr*) malloc(sizeof (pcap_pkthdr));
    header->caplen = 60;
    header->len = 60;
    header->ts = *ts;

    // this open and parse the XML file:
    XMLNode xMainNode = XMLNode::openFileHelper("/home/erich/Desktop/ks2.xml", "packets_summary");

    int count_items = xMainNode.nChildNode();

    for (int i = 0; i < 2; i++) {
        XMLNode node = xMainNode.getChildNode(i);

        index = node.getChildNode("protocol").getText();
        frame_type = node.getChildNode("frame_type").getText();
        local_mac_address = node.getChildNode("local_mac_address").getText();
        if (node.getChildNode("remote_mac_address").getText() != NULL) {
            remote_mac_address = node.getChildNode("remote_mac_address").getText();
        } else {
            remote_mac_address = set_broadcast_mac_address();
        }

        protocol = node.getChildNode("protocol").getText();
        version = node.getChildNode("version").getText();
        local_address = node.getChildNode("local_address").getText();
        remote_address = node.getChildNode("remote_address").getText();
        protocol_type = node.getChildNode("protocol_type").getText();
        local_port = node.getChildNode("local_port").getText();
        remote_port = node.getChildNode("remote_port").getText();
        if (node.getChildNode("service_name").getText() != NULL) {
            service_name = node.getChildNode("service_name").getText();
        } else {
            service_name = "";
        }

        packets = node.getChildNode("packets").getText();


        cout << local_address << endl;
        cout << parse_ip_address(local_address) << endl;



        int count_packets = str_to_int(packets, 10);

        if (!protocol_type.compare(UDP)) {
            cout << "Vytvaram UDP packet" << endl;
            char* udp_packet = create_udp_packet2(70,
                    local_mac_address,
                    remote_mac_address,
                    "4",
                    local_address,
                    remote_address,
                    "UDP",
                    "17500",
                    "17500",
                    "");

            for (int i = 0; i < count_packets; i++) {
                /*
                 * Create fake IP header and put UDP header
                 * and payload in place
                 */

                /* write packet to save file */
                pcap_dump((u_char *) cap_dumper, header, (u_char *) udp_packet);
            }
        }
        
        index = "";
        frame_type = "";
        local_mac_address = "";
        remote_mac_address = "";
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
    }
    //    
    //    XMLNode xNode=xMainNode.getChildNode(0);
    //    printf("Index: '%s'\n", xNode.getChildNode("index").getText());
    //    printf("Frame type: '%s'\n", xNode.getChildNode(4).getText());
    //    printf("Local address: '%s'\n", xNode.getChildNode(9).getText());


    /*
     *   <item>
     *       <index>1</index>
     *		<frame_type>Ethernet</frame_type>
     *               <local_mac_address>00-21-85-11-29-1b</local_mac_address>
     *		<remote_mac_address></remote_mac_address>
     *		<protocol>IP</protocol>
     *		<version>4</version>
     *		<local_address>147.175.106.141</local_address>
     *		<remote_address>255.255.255.255</remote_address>
     *		<protocol_type>UDP</protocol_type>
     *		<protocol>UDP</protocol>
     *		<local_port>17500</local_port>
     *		<remote_port>17500</remote_port>
     *		<service_name></service_name>
     *		<packets>8</packets>
     *	</item>
     *
     */








    pcap_close(cap_dead);
    pcap_dump_close(cap_dumper);




    // pcap_file_new.open("packet.pcap", ios::binary);


    //pcap_file_new.close();

    return 0;
}
