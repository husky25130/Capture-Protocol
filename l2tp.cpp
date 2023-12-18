#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <iostream>
#include <time.h>
#include <string>
#include <fstream>  
#include <bitset>
#include <queue>
#include <thread>
#include <mutex>


#include <Winsock2.h>


#include "my_l2tp.h"
using namespace std;


queue<PAK_INFO>  PAK_Q;//���ݰ�����

int pack_num = 0;           //��¼��ȡ��l2tpЭ������
pcap_t* dev_handle;           //����

u_char src_mac[6];  //src mac��ַ
u_char dst_mac[6];  //
u_char src_ip[4];
u_char dst_ip[4];   //ip

int src_port;
int dst_port;    //�˿�

u_char default_mac[6];
u_char default_ip[4];

BOOL OPT = FALSE;
mutex my_mutex;   //���ź�

fstream file;





void packet_listen()
{
    void l2tp_analysis(u_char * memo, const struct pcap_pkthdr* packet_header, const u_char * packet_info);
    pcap_loop(dev_handle, -1, l2tp_analysis, NULL);
}

/*
 *   |-------------------|
 *   |    Ethernet II    |   eth_header
 *   |-------------------|
 *   |       IPv4        |   ip_header
 *   |-------------------|
 *   |        UDP        |   udp_header
 *   |-------------------|
 *   |       L2TP        |
 *   |-------------------|
 *   |      Payload      |
 *   |-------------------|
 *
 */
void packet_capture()
{

    //file.open("get.txt", ios::out);
    //��������д������� 
  
    while (1)
    {
        while (!PAK_Q.empty())
        {
            my_mutex.lock();
            PAK_INFO PACKAGE = PAK_Q.front();    //�Ӷ���ȡ��Ϣ
            PAK_Q.pop();
            my_mutex.unlock();
          

            const unsigned char* data_addr;//���������Ч�غɵĵ�ַ

                /***************************************************************************************/
                /*************************************ETHERNET��****************************************/
                /***************************************************************************************/
            const unsigned char* ether_head = PACKAGE.pak_data;
            const unsigned char* src_MAC;                                               //ԴMAC��ַ��6bytes
            const unsigned char* dst_MAC;                                               //Ŀ��MAC��ַ
            const unsigned char* ether_protocol;                                    //��̫���ϲ�Э�����ͣ�2bytes
            dst_MAC = ether_head;
            src_MAC = ether_head + 6;
            ether_protocol = ether_head + 12;


            /***************************************************************************************/
            /*************************************IPv4��****************************************/
            /***************************************************************************************/
            if (*ether_protocol == 0x08 && *(ether_protocol + 1) == 0x00)
            {
                const unsigned char* ip_head1 = ether_head + 14;                                                    //ip��ʼλ��
                const unsigned char* src_ip1 = ip_head1 + 12;                                                       //Դip��ַ 4bytes
                const unsigned char* dst_ip1 = ip_head1 + 16;                                                       //Ŀ��ip��ַ
                const unsigned char* ip_protocol1 = ip_head1 + 9;                                                   //�ϲ�Э�� 1bytes
                const unsigned char* ip_id = ip_head1 + 4;                                                          //����id 2bytes
                int ip_head_len1 = unsigned  short(*(ip_head1) & 0x0F) * 4;                                         //ipͷ������
                const unsigned char* ip_len_addr1 = ip_head1 + 2;                                                   //ip�����ܳ��ȵ�ַ��2bytes
                unsigned  int ip_len1 = unsigned  int(*ip_len_addr1) * 256 + unsigned  int(*(ip_len_addr1 + 1));    //ip�����ܳ���
               
                int total_len = PACKAGE.pak_header->caplen;


                /***************************************************************************************/
                /*************************************UDP��*********************************************/
                /***************************************************************************************/
                if (*ip_protocol1 == 0x11)
                {

                    const unsigned char* udp_head1 = ip_head1 + ip_head_len1;                         //UDP����ʼλ��
                    const unsigned char* src_udp_port1 = udp_head1;                                   //UDP��Դ�˿ڵ�ַ
                    const unsigned char* dst_udp_port2 = udp_head1 + 2;                               //UDP��Ŀ�Ķ˿ڵ�ַ

                    int SUP1_DEC = unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1));
                    int DUP1_DEC = unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1));

                    //L2TP���������������������Ƿ���L2TPЭ��
                    const unsigned char* l2tp_head = udp_head1 + 8;                         //L2TP����ʼλ��
                    int l2tp_len = 6;                                                       //l2tpͷ�����ȣ���Ҫ������㣬��ʼΪ6
                    unsigned short l2tp_version = unsigned short(*(l2tp_head + 1));         //l2tp�汾
                    bool T, L, S, O, P;                                                     //l2tp����λ
                    bitset<8> l2tp_control = *l2tp_head;
                    bitset<8>l2tp_version_bit = *(l2tp_head + 1);

                    /// <summary>
                    /// 
                    /// </summary>
                    T = l2tp_control[7];
                    L = l2tp_control[6];
                    S = l2tp_control[3];
                    O = l2tp_control[1];
                    P = l2tp_control[0];

                    if (T && (!L || !S || O || P))                //���Ʊ���L 1,ver 2��������L2TP����;
                    {
               
                        continue;
                    }

                    if (l2tp_control[5] || l2tp_control[4] || l2tp_control[2] || l2tp_version_bit[7] || l2tp_version_bit[6] || l2tp_version_bit[5] || l2tp_version_bit[4])   //���λ��Ȼ��0��������L2TP����
                    {
                        continue;
                    }

                    BOOL FLAG1, FLAG2, FLAG3, FLAG4;
                    FLAG1 = cmp_bytes(src_ip1, src_ip, 4) || cmp_bytes(src_ip, default_ip, 4);
                    FLAG2 = cmp_bytes(dst_ip1, dst_ip, 4) || cmp_bytes(dst_ip, default_ip, 4);

                    if (T)              //�����L2TP���Ʊ��� ����Ϊֹ
                    {
                        if (!OPT)
                        {
                            pack_num++;

                            cout << endl;
                           
                            cout << endl;
                            //file << "\n\n";
                            cout << pack_num << "." << endl;
                            cout << "<=======================����һ���ָ���=========================>";
                            //print_bytes(ether_head, total_len);
                            cout << endl;
                            cout << endl;
                            cout << "ETHERNET LAYER��" << endl;
                            cout << "ԴMAC��";
                            print_mac(src_MAC);
                            cout << endl;
                            cout << "Ŀ��MAC��";
                            print_mac(dst_MAC);
                            cout << endl;
                            cout << endl;

                            cout << "FIRST IPV4 LAYER:" << endl;
                            cout << "ԴIP��ַ��";
                            print_ip(src_ip1);
                            cout << endl;
                            cout << "Ŀ��IP��ַ��";
                            print_ip(dst_ip1);
                            cout << endl;
                            cout << "ID��" << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                            cout << endl;
                            cout << endl;

                            cout << "FIRST UDP LAYER:" << endl;
                            cout << "Դ�˿ڣ�" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                            cout << endl;
                            cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                            cout << endl;
                            cout << endl;

                            cout << "L2TP_ControlMessage ����" << endl;
                            cout << endl;

                      
                            continue;
                        }
                        else
                        {
                            if (!(FLAG1 && FLAG2))
                                continue;
                            else
                            {
                                pack_num++;

                                cout << endl;    cout << endl;
                                cout << pack_num << "." << endl;
                                
                                cout << "<=======================����һ���ָ���=========================>";
                                //print_bytes(ether_head, total_len);
                                cout << endl;
                                cout << endl;
                                cout << "ETHERNET LAYER��" << endl;
                                cout << "ԴMAC��";
                                print_mac(src_MAC);
                                cout << endl;
                                cout << "Ŀ��MAC��";
                                print_mac(dst_MAC);
                                cout << endl;
                                cout << endl;

                                cout << "FIRST IPV4 LAYER:" << endl;
                                cout << "ԴIP��ַ��";
                                print_ip(src_ip1);
                                cout << endl;
                                cout << "Ŀ��IP��ַ��";
                                print_ip(dst_ip1);
                                cout << endl;
                                cout << "ID��" << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                cout << endl;
                                cout << endl;

                                cout << "FIRST UDP LAYER:" << endl;
                                cout << "Դ�˿ڣ�" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                cout << endl;
                                cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                cout << endl;
                                cout << endl;

                                cout << "L2TP_ControlMessage ����" << endl;
                                cout << endl;
                            }
                        }
                    }


                    /***************************************************************************************/
                    /*************************************L2TP��****************************************/
                    /***************************************************************************************/
                    //���ݿ���λ����ʼ��L2TP���ĳ���
                    if (L)
                        l2tp_len += 2;
                    if (S)
                        l2tp_len += 4;
                    if (O)
                        l2tp_len += 2;

                    const unsigned char* l2tp_tunel;                //L2TP��Tunel��ʼλ��
                    const unsigned char* l2tp_session;               //L2TP��session��ʼλ��
                    if (L)
                    {
                        l2tp_tunel = l2tp_head + 4;                 //L2TP��Tunel��ʼλ��
                        l2tp_session = l2tp_head + 6;                //L2TP��session��ʼλ��
                    }
                    else
                    {
                        l2tp_tunel = l2tp_head + 2;                 //L2TP��Tunel��ʼλ��
                        l2tp_session = l2tp_head + 4;               //L2TP��session��ʼλ��
                    }
                    
                    int l2tp_tunel_id = unsigned int(*l2tp_tunel) * 256 + unsigned int(*(l2tp_tunel + 1));
                    int l2tp_session_id = unsigned int(*l2tp_session) * 256 + unsigned int(*(l2tp_session + 1));


                /***************************************************************************************/
                /*************************************PPP��*********************************************/
                /***************************************************************************************/
                    const unsigned char* ppp_head = l2tp_head + l2tp_len; //ppp��ʼ��ַ
                    const unsigned char* ppp_addr = ppp_head;//ppp��ַλ��1bytes
                    const unsigned char* ppp_control = ppp_head + 1;//ppp����λ��1bytes


                    //ppp_flag��ppp_addr��ppp_control��ͬȷ���Ƿ���ppp����  fff 03

                    if (*ppp_addr != 0xFF || *ppp_control != 0x03)
                    {
                        
                        continue;
                    }


                    BOOL SMAC, DMAC, SIP, DIP, SPORT, DPORT;       //���˿���λ

                    if (!OPT)
                    {
                        pack_num++;
                        cout << endl;    cout << endl;
                        cout << pack_num << "." << endl;
                        cout << "<=======================����һ���ָ���=========================>";
                        //print_bytes(ether_head, total_len);
                        cout << endl;
                        cout << endl;
                        cout << "ETHERNET LAYER��" << endl;
                        cout << "ԴMAC��";
                        print_mac(src_MAC);
                        cout << endl;
                        cout << "Ŀ��MAC��";
                        print_mac(dst_MAC);
                        cout << endl;
                        cout << endl;

                        cout << "FIRST IPV4 LAYER:" << endl;
                        cout << "ԴIP��ַ��";
                        print_ip(src_ip1);
                        cout << endl;
                        cout << "Ŀ��IP��ַ��";
                        print_ip(dst_ip1);
                        cout << endl;
                        cout << "ID��";
                        cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                        cout << endl;
                        cout << endl;


                        cout << "FIRST UDP LAYER:" << endl;
                        cout << "Դ�˿ڣ�" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                        cout << endl;
                        cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                        cout << endl;
                        cout << endl;

                        cout << "*L2TP LAYER:" << endl;
                        cout << "Tunel_ID��" << l2tp_tunel_id << endl;
                        cout << "Session_ID��" << l2tp_session_id << endl;

                        cout << endl;
                        cout << "PPP LAYER:" << endl;
                        cout << endl;
                    }
                    else
                    {
                        SMAC = cmp_bytes(src_MAC, src_mac, 6) || cmp_bytes(src_mac, default_mac, 6);
                        DMAC = cmp_bytes(dst_MAC, dst_mac, 6) || cmp_bytes(dst_mac, default_mac, 6);
                        if (!(SMAC && DMAC))
                            continue;
                    }

                    /***************************************************************************************/
                    /*************************************PPP IPv4��****************************************/
                    /***************************************************************************************/
                    const unsigned char* ppp_protocol1 = ppp_head + 2;              //ppp�ϲ�Э���־1��1bytes
                    const unsigned char* ppp_protocol2 = ppp_head + 3;              //ppp�ϲ�Э���־2��1bytes
                    //IP��2����
                    if (*ppp_protocol1 == 0x00 && *ppp_protocol2 == 0x21) //ipЭ��
                    {
                        //IP��2
                        const unsigned char* ip_head2 = ppp_head + 4;                                                            //ip��ʼλ��
                        const unsigned char* src_ip2 = ip_head2 + 12;                                                           //Դip��ַ��4bytes
                        const unsigned char* dst_ip2 = ip_head2 + 16;                                                            //Ŀ��ip��ַ
                        const unsigned char* ip_protocol2 = ip_head2 + 9;                                                       //�ϲ�Э�� 1bytes
                        const unsigned char* ip_id2 = ip_head2 + 4;                                                             //����id 2bytes
                        const unsigned char* ip_len_addr2 = ip_head2 + 2;                                                        //ip�����ܳ��ȵ�ַ��2bytes
                        unsigned  int ip_head_len2 = unsigned  int(*(ip_head2) & 0x0F) * 4;                                     //ipͷ������
                        unsigned  int ip_len2 = unsigned  int(*ip_len_addr2) * 256 + unsigned  int(*(ip_len_addr2 + 1));        // ip�����ܳ���

                        if (!OPT)
                        {
                            cout << "SECOND IPV4 LAYER:" << endl;
                            cout << "ԴIP��ַ��";
                            print_ip(src_ip2);
                            cout << endl;
                            cout << "Ŀ��IP��ַ��";
                            print_ip(dst_ip2);
                            cout << endl;
                            cout << "ID��";
                            cout << (unsigned short(*ip_id2) * 256 + unsigned short(*(ip_id2 + 1)));
                            cout << endl;
                            cout << endl;
                        }
                        else
                        {
                            SIP = cmp_bytes(src_ip2, src_ip, 4) || cmp_bytes(src_ip1, src_ip, 4) || cmp_bytes(src_ip, default_ip, 4);
                            DIP = cmp_bytes(dst_ip2, dst_ip, 4) || cmp_bytes(dst_ip1, dst_ip, 4) || cmp_bytes(dst_ip, default_ip, 4);
                            if (!(SIP && DIP))
                                continue;
                        }

                        //���������UDP/TCP

                        const unsigned char* inner_head = ip_head2 + ip_head_len2;  
                        unsigned  int inner_len = ip_len2 - ip_head_len2;                       //����㱨�ĳ���
                        const unsigned char* SP2 = inner_head;                                  //UDP\TCP��Դ�˿ڵ�ַ
                        const unsigned char* DP2 = inner_head + 2;                              //UDP\TCP��Ŀ�Ķ˿ڵ�ַ
                        int SP2V = unsigned int(*SP2) * 256 + unsigned int(*(SP2 + 1));
                        int DP2V = unsigned int(*DP2) * 256 + unsigned int(*(DP2 + 1));

                        FLAG3 = (SUP1_DEC == src_port) || (src_port == 0);
                        FLAG4 = (DUP1_DEC == dst_port) || (dst_port == 0);

                        if (*ip_protocol2 == 0x11)  //UDP
                        {
                            if (!OPT)
                            {
                                /***********************/
                                cout << "SECOND UDP LAYER:" << endl;
                                cout << "Դ�˿ڣ�" << (unsigned int(*SP2) * 256 + unsigned int(*(SP2 + 1)));
                                cout << endl;
                                cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*DP2) * 256 + unsigned int(*(DP2 + 1)));
                                cout << endl;
                                cout << endl;
                                data_addr = get_datas(0x11, inner_head, inner_len);
                            }
                            else
                            {
                                SPORT = (SP2V == src_port) || (SUP1_DEC == src_port) || (src_port == 0);
                                DPORT = (DP2V == dst_port) || (DUP1_DEC == dst_port) || (dst_port == 0);
                                if (!(SPORT && DPORT))
                                    continue;
                                else
                                {
                                    pack_num++;
                                    cout << endl;    cout << endl;
                                    cout << pack_num << "." << endl;
                                    cout << "<=======================����һ���ָ���=========================>";
                                   
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "ETHERNET LAYER��" << endl;
                                    cout << "ԴMAC��";
                                    print_mac(src_MAC);
                                    cout << endl;
                                    cout << "Ŀ��MAC��";
                                    print_mac(dst_MAC);
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "FIRST IPV4 LAYER:" << endl;
                                    cout << "ԴIP��ַ��";
                                    print_ip(src_ip1);
                                    cout << endl;
                                    cout << "Ŀ��IP��ַ��";
                                    print_ip(dst_ip1);
                                    cout << endl;
                                    cout << "ID��";
                                    cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "FIRST UDP LAYER:" << endl;
                                    cout << "Դ�˿ڣ�" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                    cout << endl;
                                    cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "*L2TP LAYER:" << endl;
                                    cout << "Tunel_ID��" << l2tp_tunel_id << endl;
                                    cout << "Session_ID��" << l2tp_session_id << endl;

                                    cout << endl;

                                    /***********************/
                                    cout << "PPP LAYER:" << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "SECOND IPV4 LAYER:" << endl;
                                    cout << "ԴIP��ַ��";
                                    print_ip(src_ip2);
                                    cout << endl;
                                    cout << "Ŀ��IP��ַ��";
                                    print_ip(dst_ip2);
                                    cout << endl;
                                    cout << "ID��";
                                    cout << (unsigned short(*ip_id2) * 256 + unsigned short(*(ip_id2 + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "SECOND UDP LAYER:" << endl;
                                    cout << "Դ�˿ڣ�" << (unsigned int(*SP2) * 256 + unsigned int(*(SP2 + 1)));
                                    cout << endl;
                                    cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*DP2) * 256 + unsigned int(*(DP2 + 1)));
                                    cout << endl;
                                    cout << endl;
                                    data_addr = get_datas(0x11, inner_head, inner_len);
                                }
                            }
                        }//end of udp
                        else if (*ip_protocol2 == 0x06)  //TCP
                        {
                            if (!OPT)
                            {
                                cout << "TCP LAYER" << endl;
                                cout << "Դ�˿ڣ�" << (unsigned int(*SP2) * 256 + unsigned int(*(SP2 + 1)));
                                cout << endl;
                                cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*DP2) * 256 + unsigned int(*(DP2 + 1)));
                                cout << endl;
                                cout << endl;
                                data_addr = get_datas(0x06, inner_head, inner_len);
                            }
                            else
                            {
                                SPORT = (SP2V == src_port) || (src_port == 0);
                                DPORT = (DP2V == src_port) || (src_port == 0);
                                if (!(SPORT && DPORT))
                                    continue;
                                else
                                {
                                    pack_num++;
                                    cout << endl;    cout << endl;
                                    cout << pack_num << "." << endl;
                                    cout << "<=======================����һ���ָ���=========================>";
                                    
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "ETHERNET LAYER��" << endl;
                                    cout << "ԴMAC��";
                                    print_mac(src_MAC);
                                    cout << endl;
                                    cout << "Ŀ��MAC��";
                                    print_mac(dst_MAC);
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "FIRST IPV4 LAYER:" << endl;
                                    cout << "ԴIP��ַ��";
                                    print_ip(src_ip1);
                                    cout << endl;
                                    cout << "Ŀ��IP��ַ��";
                                    print_ip(dst_ip1);
                                    cout << endl;
                                    cout << "ID��";
                                    cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "FIRST UDP LAYER:" << endl;
                                    cout << "Դ�˿ڣ�" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                    cout << endl;
                                    cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "*L2TP LAYER:" << endl;
                                    cout << "Tunel_ID��" << l2tp_tunel_id << endl;
                                    cout << "Session_ID��" << l2tp_session_id << endl;

                                    cout << endl;

                                    /***********************/
                                    cout << "PPP LAYER:" << endl;
                                    cout << endl;
                                    /***********************/
                                    cout << "SECOND IPV4 LAYER:" << endl;
                                    cout << "ԴIP��ַ��";
                                    print_ip(src_ip2);
                                    cout << endl;
                                    cout << "Ŀ��IP��ַ��";
                                    print_ip(dst_ip2);
                                    cout << endl;
                                    cout << "ID��";
                                    cout << (unsigned short(*ip_id2) * 256 + unsigned short(*(ip_id2 + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "SECOND UDP LAYER:" << endl;
                                    cout << "Դ�˿ڣ�" << (unsigned int(*SP2) * 256 + unsigned int(*(SP2 + 1)));
                                    cout << endl;
                                    cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*DP2) * 256 + unsigned int(*(DP2 + 1)));
                                    cout << endl;
                                    cout << endl;
                                    data_addr = get_datas(0x11, inner_head, inner_len);
                                }
                            }
                        }//end of tcp

                        else if (*ip_protocol2 == 0x01)//ICMP
                        {
                            if (!OPT)
                            {
                                cout << "ICMP����";
                                cout << endl;
                            }
                            else
                            {
                                if (!(SIP && DIP && FLAG3 && FLAG4))
                                    continue;
                                else
                                {
                                    pack_num++;
                                    cout << endl;    cout << endl;
                                    cout << pack_num << "." << endl;
                                    cout << "<=======================����һ���ָ���=========================>";
                                    cout << endl;
                                    cout << endl;
                                    cout << "ETHERNET LAYER��" << endl;
                                    cout << "ԴMAC��";
                                    print_mac(src_MAC);
                                    cout << endl;
                                    cout << "Ŀ��MAC��";
                                    print_mac(dst_MAC);
                                    cout << endl;
                                    cout << endl;
                                    /***********************/

                                    cout << "FIRST IPV4 LAYER:" << endl;
                                    cout << "ԴIP��ַ��";
                                    print_ip(src_ip1);
                                    cout << endl;
                                    cout << "Ŀ��IP��ַ��";
                                    print_ip(dst_ip1);
                                    cout << endl;
                                    cout << "ID��";
                                    cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "FIRST UDP LAYER:" << endl;
                                    cout << "Դ�˿ڣ�" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                    cout << endl;
                                    cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "*L2TP LAYER:" << endl;
                                    cout << "Tunel_ID��" << l2tp_tunel_id << endl;
                                    cout << "Session_ID��" << l2tp_session_id << endl;

                                    cout << endl;
                                    /***********************/
                                    cout << "PPP LAYER:" << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "SECOND IPV4 LAYER:" << endl;
                                    cout << "ԴIP��ַ��";
                                    print_ip(src_ip2);
                                    cout << endl;
                                    cout << "Ŀ��IP��ַ��";
                                    print_ip(dst_ip2);
                                    cout << endl;
                                    cout << "ID��";
                                    cout << (unsigned short(*ip_id2) * 256 + unsigned short(*(ip_id2 + 1)));
                                    cout << endl;
                                    cout << endl;
                                }
                            }
                        }//end of icmp

                    }  //end of ip
                    else if (*ppp_protocol1 == 0xC0 && *ppp_protocol2 == 0x21)  //LCP
                    {
                        if (!OPT)
                        {
                            cout << "LCP����" << endl;
                        }
                        else
                        {
                            if (!(FLAG1 && FLAG2 && FLAG3 && FLAG4))
                                continue;
                            else
                            {
                                pack_num++;
                                cout << endl;    cout << endl;
                                cout << pack_num << "." << endl;
                                cout << "<=======================����һ���ָ���=========================>";
                                //print_bytes(ether_head, total_len);
                                cout << endl;
                                cout << endl;
                                /***********************/
                                cout << "ETHERNET LAYER��" << endl;
                                cout << "ԴMAC��";
                                print_mac(src_MAC);
                                cout << endl;
                                cout << "Ŀ��MAC��";
                                print_mac(dst_MAC);
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "FIRST IPV4 LAYER:" << endl;
                                cout << "ԴIP��ַ��";
                                print_ip(src_ip1);
                                cout << endl;
                                cout << "Ŀ��IP��ַ��";
                                print_ip(dst_ip1);
                                cout << endl;
                                cout << "ID��";
                                cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "FIRST UDP LAYER:" << endl;
                                cout << "Դ�˿ڣ�" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                cout << endl;
                                cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "*L2TP LAYER:" << endl;
                                cout << "Tunel_ID��" << l2tp_tunel_id << endl;
                                cout << "Session_ID��" << l2tp_session_id << endl;

                                /***********************/
                                cout << endl;
                                cout << "PPP LAYER:" << endl;
                                cout << endl;
                                cout << "LCP����" << endl;
                            }
                        }
                    }//end of lcp
                    else if (*ppp_protocol1 == 0xC2 && *ppp_protocol2 == 0x23)   //CHAP
                    {
                        if (!OPT)
                        {
                            cout << "CHAP����" << endl;
                        }
                        else
                        {
                            if (!(FLAG1 && FLAG2 && FLAG3 && FLAG4))
                                continue;
                            else
                            {
                                pack_num++;
                                cout << endl;    cout << endl;
                                cout << pack_num << "." << endl;
                                cout << "<=======================����һ���ָ���=========================>";
                                //print_bytes(ether_head, total_len);
                                cout << endl;
                                cout << endl;
                                /***********************/
                                cout << "ETHERNET LAYER��" << endl;
                                cout << "ԴMAC��";
                                print_mac(src_MAC);
                                cout << endl;
                                cout << "Ŀ��MAC��";
                                print_mac(dst_MAC);
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "FIRST IPV4 LAYER:" << endl;
                                cout << "ԴIP��ַ��";
                                print_ip(src_ip1);
                                cout << endl;
                                cout << "Ŀ��IP��ַ��";
                                print_ip(dst_ip1);
                                cout << endl;
                                cout << "ID��";
                                cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "FIRST UDP LAYER:" << endl;
                                cout << "Դ�˿ڣ�" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                cout << endl;
                                cout << "Ŀ�Ķ˿ڣ�" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "*L2TP LAYER:" << endl;
                                cout << "Tunel_ID��" << l2tp_tunel_id << endl;
                                cout << "Session_ID��" << l2tp_session_id << endl;

                                cout << endl;

                                /***********************/
                                cout << "PPP LAYER:" << endl;
                                cout << endl;
                                cout << "CHAP����" << endl;
                            }
                        }
                    }//end of CHAP

                }//end of ppp ipv4
                else
                {
                    
                    continue;
                }
            }
            
        }
    }
    file.close();
}

int listen_num = 0;

void l2tp_analysis(u_char* memo, const struct pcap_pkthdr* packet_header, const u_char* packet_info)
{
    PAK_INFO PACKAGE;

    pcap_pkthdr* p_head = new pcap_pkthdr;
    p_head->caplen = packet_header->caplen;
    p_head->len = packet_header->len;
    p_head->ts = packet_header->ts;

    u_char* p_data = new u_char[packet_header->caplen];
    memcpy(p_data, packet_info, packet_header->caplen);

    PACKAGE.pak_data = p_data;
    PACKAGE.pak_header = p_head;

    my_mutex.lock();
    PAK_Q.push(PACKAGE);
    my_mutex.unlock();

}


int main()
{

    src_port = 0;
    dst_port = 0;

    memset(default_mac, 0, 6);
    memset(default_ip, 0, 4);
    memset(src_mac, 0, 6);
    memset(dst_mac, 0, 6);
    /*
    * 
    * pcap_if_t��typedef struct pcap_if pcap_if_t ��������������Ϣ�����͡�ͨ����ָ����ʹ�ã�pcap_if_t *my_devs
    * struct pcap_if
    * {
    * struct pcap_if *next;             //ָ����һ������
    * char *name;                       //�����ı�ʶ����Ψһʶ��һ������
    * char *description;                //������������
    * struct pcap_addr*address;         //�����ĵ�ַ������IP��ַ���������룬�㲥��ַ�ȣ������еĳ�Ա�����ں����д��
    * bpf_u_int32 flags;                //�ӿڱ�־
    * 
    */
    pcap_if_t* my_devs, * tmp_devs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // �ҳ�����������Ϣ
    if (pcap_findalldevs(&my_devs, errbuf) == -1)   //������
    {
        fprintf(stderr, "Error in pcap_findalldevs:%s\n", errbuf);
        exit(1);
    }

    //  ��ӡ����������Ϣ
    int i = 0;
    for (tmp_devs = my_devs; tmp_devs; tmp_devs = tmp_devs->next)
    {
        printf("%d : %s", ++i, tmp_devs->name);
        if (tmp_devs->description)
            printf(" (%s)\n", tmp_devs->description);
        else
            printf(" (No description available)\n");
    }


    //������
    int inum;
    printf("\n<=====��ѡ����Ҫ���������� (1-%d)=====>:\t", i);
    scanf("%d", &inum);               //����Ҫѡ��򿪵�������

    for (tmp_devs = my_devs, i = 0; i < inum - 1; tmp_devs = tmp_devs->next, i++);               //�ҵ�ѡ�������

    dev_handle = pcap_open_live(tmp_devs->name, 65536, 0, 1000, errbuf);
    pcap_freealldevs(my_devs);

    cout << endl;
    cout << "<====�Ƿ����ip/�˿ڹ��ˣ�����1(��)��0(��)===>" << endl;
    cin >> OPT;

    if (OPT)
    {


        cout << "��������˵�src ip��0.0.0.0��ʾ�����ˣ���" << endl;     //10����
        for (int i = 0; i < 4; i++)
        {
            if (i < 3)
                scanf("%hhu.", src_ip + i);
            else
                scanf("%hhu", src_ip + i);
            
        }
        cout << "��������˵�dst ip��0.0.0.0��ʾ�����ˣ���" << endl;     //10����
        for (int i = 0; i < 4; i++)
        {
            if (i < 3)
                scanf("%hhu.", dst_ip + i);
            else
                scanf("%hhu", dst_ip + i);

        }


        cout << "���������src�˿ڣ�0��ʾ�����ˣ���" << endl;
        cin >> src_port;

        cout << "���������dst�˿ڣ�0��ʾ�����ˣ���" << endl;
        cin >> dst_port;
       
        

        cout << "���ڼ�����... ��ȴ�\n";
    }
    else
        cout << "���ڼ�����... ��ȴ�\n";


    /******
    *  ����������
    *  һ������������һ���������������Ϳ��Լ��ٶ���
    *****/
    thread  _listen_(packet_listen);          
    thread  _capture_(packet_capture);              

    _listen_.join();
    _capture_.join();


    return 0;
}


