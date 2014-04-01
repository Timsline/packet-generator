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

class IPPacket {

};

class IPXPacket {

};

int str_to_int(string text) {
    return stoi(text, NULL, 16);
}

int str_to_int(string text, int base) {
    return stoi(text, NULL, base);
}

//00-00-00-00-00-00
string parse_mac_address(string mac_address) {    
    auto it = std::remove_if(std::begin(mac_address),std::end(mac_address),[](char c){return (c == '-');});
    mac_address.erase(it, std::end(mac_address));
   
    return mac_address;
}


char * substr(string s, int x, int y)
{
    char *ret = (char*)malloc(18);
    char * p = ret;
    char * q = &s[x];
    

    
    
    while(x  < y)
    {
        *p++ = *q++;
        x ++;
    }
    
    *p++ = '\0';
    
    return ret;
}

char* create_udp_packet(int size_of_packet) {
    char* packet;
    packet = (char*)malloc((size_of_packet)*1);
    
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
    packet[6] = str_to_int(substr(mac,0,2));
    packet[7] = str_to_int(substr(mac,2,4));
    packet[8] = str_to_int(substr(mac,4,6));
    packet[9] = str_to_int(substr(mac,6,8));
    packet[10] = str_to_int(substr(mac,8,10));
    packet[11] = str_to_int(substr(mac,10,12));    
    for (int i = 6; i <= 11; i++) {
        packet[i] = str_to_int(substr(mac,i,i+2));
    }        
    // set IP protocol 0x0800

    packet[12]  = 0x08;
    packet[13]  = 0x00;
    
    // IPv4 = 0x45
    packet[14]  = 0x45;
    
    // ??
    packet[15]  = 0x00;
    
    // length IP
    packet[16]  = 0x00;
    packet[17]  = 0x00;
    
    // identification
    packet[18]  = 0x00;
    packet[19]  = 0x00;
    
    // flags
    packet[20]  = 0x00;
    
    
    packet[21]  = 0x00;
    
    // Time To Live - TTL  128?
    packet[22]  = 0x40;
    
    // protocol UDP
    packet[23]  = str_to_int("17",10);
    
    // UDP header checksum
    packet[24]  = 0x00;
    packet[25]  = 0x00;
    
    // IP source address 147.175.106.141
    packet[26]  = str_to_int("147",10);
    packet[27]  = str_to_int("175",10);
    packet[28]  = str_to_int("106",10);
    packet[29]  = str_to_int("141",10);
    
    // IP destination address
    packet[30]  = str_to_int("255",10);
    packet[31]  = str_to_int("255",10);
    packet[32]  = str_to_int("255",10);
    packet[33]  = str_to_int("255",10);
    
    // UDP information
    // udp source port
    packet[34]  = str_to_int("44");
    packet[35]  = str_to_int("5c");
    
    // udp destination port
    packet[36]  = str_to_int("44");
    packet[37]  = str_to_int("5c");
    
    // udp length
    packet[38]  = 0x00;
    packet[39]  = 0x14;
    
    // check sum
    packet[40]  = 0x00;
    packet[41]  = 0x00;
    
    
    // data 50:69:76:61:72:6e:69:6b:20:6a:65:20:68:6f:6d:6f:73:20:3a:44
    packet[42]  = 0x50;
    packet[43]  = 0x69;
    packet[44]  = 0x76;
    packet[45]  = 0x61;
    
    packet[46]  = 0x72;
    packet[47]  = 0x6e;
    packet[48]  = 0x69;
    packet[49]  = 0x6b;
    packet[50]  = 0x20;
    packet[51]  = 0x6a;
    packet[52]  = 0x65;
    packet[53]  = 0x20;
    
    packet[54]  = 0x68;
    packet[55]  = 0x6f;
    packet[56]  = 0x6d;
    packet[57]  = 0x6f;
    packet[58]  = 0x73;
    packet[59]  = 0x20;
    packet[60]  = 0x3a;
    packet[61]  = 0x44;
    
    return packet;
}

char* create_tcp_packet(int size_of_packet) {
    char* packet;
    packet = (char*)malloc((size_of_packet)*1);
    
    // mac destination address to 00-00-00-00-00-00
    packet[0] = 0;
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 0;
    packet[4] = 0;
    packet[5] = 0;
    
    // set mac source address to 00-21-85-11-29-1b
    packet[6] = str_to_int("00");
    packet[7] = str_to_int("21");
    packet[8] = str_to_int("85");
    packet[9] = str_to_int("11");
    packet[10] = str_to_int("29");
    packet[11] = str_to_int("1b");    
            
    // set IP protocol 0x0800

    packet[12]  = 0x08;
    packet[13]  = 0x00;
    
    // IPv4 = 0x45
    packet[14]  = 0x45;
    
    // ??
    packet[15]  = 0x00;
    
    // length IP
    packet[16]  = 0x00;
    packet[17]  = 0x00;
    
    // identification
    packet[18]  = 0x00;
    packet[19]  = 0x00;
    
    // flags
    packet[20]  = 0x00;
    
    
    packet[21]  = 0x00;
    
    // Time To Live - TTL  128?
    packet[22]  = 0x40;
    
    // protocol UDP
    packet[23]  = str_to_int("17",10);
    
    // UDP header checksum
    packet[24]  = 0x00;
    packet[25]  = 0x00;
    
    // IP source address 147.175.106.141
    packet[26]  = str_to_int("147",10);
    packet[27]  = str_to_int("175",10);
    packet[28]  = str_to_int("106",10);
    packet[29]  = str_to_int("141",10);
    
    // IP destination address
    packet[30]  = str_to_int("255",10);
    packet[31]  = str_to_int("255",10);
    packet[32]  = str_to_int("255",10);
    packet[33]  = str_to_int("255",10);
    
    // UDP information
    // udp source port
    packet[34]  = str_to_int("44");
    packet[35]  = str_to_int("5c");
    
    // udp destination port
    packet[36]  = str_to_int("44");
    packet[37]  = str_to_int("5c");
    
    // udp length
    packet[38]  = 0x00;
    packet[39]  = 0x14;
    
    // check sum
    packet[40]  = 0x00;
    packet[41]  = 0x00;
    
    
    // data 50:69:76:61:72:6e:69:6b:20:6a:65:20:68:6f:6d:6f:73:20:3a:44
    packet[42]  = 0x50;
    packet[43]  = 0x69;
    packet[44]  = 0x76;
    packet[45]  = 0x61;
    
    packet[46]  = 0x72;
    packet[47]  = 0x6e;
    packet[48]  = 0x69;
    packet[49]  = 0x6b;
    packet[50]  = 0x20;
    packet[51]  = 0x6a;
    packet[52]  = 0x65;
    packet[53]  = 0x20;
    
    packet[54]  = 0x68;
    packet[55]  = 0x6f;
    packet[56]  = 0x6d;
    packet[57]  = 0x6f;
    packet[58]  = 0x73;
    packet[59]  = 0x20;
    packet[60]  = 0x3a;
    packet[61]  = 0x44;
    
    return packet;
}

void create_ipx_packet() {
    char packet[58];
}

int main(int argc, char **argv)
{
    int index;
    string frame_type;
    string local_mac_address;
    string remote_mac_address;
    string protocol;
    int version;
    string local_address;
    string remote_address;
    string protocol_type;
    string protocol_transport;
    string local_port;
    string remote_port;
    string service_name;
    string packets;

    //ofstream pcap_file_new;
    char file_name[] = "packet.pcap";

    //parse_mac_address("00-21-85-11-29-1b");

    // is called to open a ``savefile'' for writing. fname specifies the name of the file to open.

    //pcap_dumper_t *pcap_dump_open(file_name);

    /*
     * Use libpcap or WinPcap - pcap_open_dead() to get a
     * "fake" pcap_t to use with pcap_dump_open() to specify
     *  the link-layer header type (for Ethernet, use DLT_EN10MB)
     * and snapshot length (use 65535), pcap_dump_open() to open the
     *  file for writing, pcap_dump() to write out a packet, and pcap_dump_close()
     *  to close the file. MUCH easier than directly using fopen(), fwrite(), and
     * fclose() (which are what libpcap/WinPcap use "under the hood").
     *
     */


    pcap_t *cap_dead;
    pcap_dumper_t *cap_dumper;
   

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
    

    
    cap_dead = pcap_open_dead(DLT_EN10MB, 65535);

    // create the output file
    cap_dumper = pcap_dump_open(cap_dead, file_name);

    timeval *ts = (timeval*)malloc(sizeof(timeval));
    ts->tv_sec = time(NULL);
    ts->tv_usec = 0;

    //creation of header
    pcap_pkthdr *header = (pcap_pkthdr*)malloc(sizeof(pcap_pkthdr));
    header->caplen = 60;
    header->len = 60;
    header->ts = *ts;


    /*
     int main()
{    
     pcap_t *m_p;
     pcap_dumper_t *m_pd;
     m_p = pcap_open_dead ( DLT_RAW, 65535 );

     m_pd = pcap_dump_open ( m_p, ( char * ) "abc.pcap" );

     char a[100] = "\0";
     strcpy(a,"name");
     struct pcap_pkthdr p;
     p.caplen = strlen(a) + 1;
     p.len = p.caplen;

     pcap_dump ( ( u_char * ) m_p, &p, ( u_char * )  a );

     pcap_close(m_p);
     pcap_dump_close(m_pd);

     return 0;        
}
     
     */
    /*
    header.caplen = strlen(packet) + 1;
    header.len = header.caplen;
    */
    
    char* udp_packet = create_udp_packet(70);
    char* tcp_packet = create_tcp_packet(70);
    
    for (int i = 0; i < 6; i++) {
        /*
         * Create fake IP header and put UDP header
         * and payload in place
         */

        /* write packet to save file */
        pcap_dump((u_char *) cap_dumper, header, (u_char *) udp_packet);
    }


    pcap_close(cap_dead);
    pcap_dump_close(cap_dumper);


    // this open and parse the XML file:
    XMLNode xMainNode=XMLNode::openFileHelper("/home/erich/Desktop/ks2.xml","packets_summary");

    // this prints "<Condor>":
    XMLNode xNode=xMainNode.getChildNode(0);
    printf("Index: '%s'\n", xNode.getChildNode("index").getText());
    printf("Frame type: '%s'\n", xNode.getChildNode(4).getText());
    printf("Local address: '%s'\n", xNode.getChildNode(9).getText());

   // pcap_file_new.open("packet.pcap", ios::binary);


    //pcap_file_new.close();

    return 0;
}
