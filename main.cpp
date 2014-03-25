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

/*
*   Author: Erich Stark
*
*
*
*/

#include <stdio.h>    // to get "printf" function
#include <stdlib.h>   // to get "free" function
#include <iostream>
#include <fstream>
#include <string.h>
#include <string>
#include "xmlparser.h"

#include <pcap.h>

using namespace std;

class IPPacket {

};

class IPXPacket {

};

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
    char file_name[] = "ahoj.pcap";



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
   

    //struct pcap_pkthdr header;
    //u_char *pkt_data;
    char packet[58];
    
    // mac destination address to 00-00-00-00-00-00
    packet[0] = 0x00;
    packet[1] = 0x00;
    packet[2] = 0x00;
    packet[3] = 0x00;
    packet[4] = 0x00;
    packet[5] = 0x00;
    
    // set mac source address to 00-21-85-11-29-1b
    packet[6]  = 0;
    packet[7] = stoi("00", NULL, 16);
    packet[8]  = stoi("85", NULL, 16);
    packet[9]  = stoi("11", NULL, 16);
    packet[10] = stoi("29", NULL, 16);
    packet[11] = stoi("1b", NULL, 16);    
            
    // set the rest of the packet

    packet[12]  = 0x08;
    packet[13]  = 0x00;
    
    packet[14]  = 0x45;
    packet[15]  = 0x00;
    packet[16]  = 0x00;
    packet[17]  = 0x2c;
    
    packet[18]  = 0x00;
    packet[19]  = 0xfb;
    
    packet[20]  = 0x40;
    packet[21]  = 0x00;
    packet[22]  = 0x40;
    packet[23]  = 0x06;
    
    packet[24]  = 0xb6;
    packet[25]  = 0x7d;
    
    packet[26]  = 0xc0;
    packet[27]  = 0xa8;
    packet[28]  = 0x01;
    packet[29]  = 0x01;
    packet[30]  = 0xc0;
    packet[31]  = 0xa8;
    packet[32]  = 0x01;
    packet[33]  = 0x02;
    
    packet[34]  = 0x04;
    packet[35]  = 0x15;
    packet[36]  = 0x00;
    packet[37]  = 0xa6;
    
    packet[38]  = 0x4d;
    packet[39]  = 0x62;
    packet[40]  = 0xfe;
    packet[41]  = 0x09;
    
    packet[42]  = 0x17;
    packet[43]  = 0x46;
    packet[44]  = 0x60;
    packet[45]  = 0x5c;
    
    packet[46]  = 0x50;
    packet[47]  = 0x18;
    packet[48]  = 0xff;
    packet[49]  = 0xff;
    packet[50]  = 0x7d;
    packet[51]  = 0x15;
    packet[52]  = 0x00;
    packet[53]  = 0x00;
    
    packet[54]  = 0x74;
    packet[55]  = 0x65;
    packet[56]  = 0x73;
    packet[57]  = 0x74;

    // fill header 
    /*
    header->caplen = 454;
    header->len = 65535;
    header->ts->tv_sec = ;
    header->ts->tv_usec = ;
    */
    
    //printf("Grabbed packet of length %d\n",header->len);
    //printf("Recieved at ..... %s\n",ctime((const time_t*) header->ts->tv_sec)); 
    
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
    
    //while (1) {
        /*
         * Create fake IP header and put UDP header
         * and payload in place
         */

        /* write packet to save file */
        pcap_dump((u_char *) cap_dumper, header, (u_char *) packet);
    //}


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
