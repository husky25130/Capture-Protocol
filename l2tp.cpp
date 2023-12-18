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


queue<PAK_INFO>  PAK_Q;//数据包队列

int pack_num = 0;           //纪录获取的l2tp协议数量
pcap_t* dev_handle;           //网卡

u_char src_mac[6];  //src mac地址
u_char dst_mac[6];  //
u_char src_ip[4];
u_char dst_ip[4];   //ip

int src_port;
int dst_port;    //端口

u_char default_mac[6];
u_char default_ip[4];

BOOL OPT = FALSE;
mutex my_mutex;   //锁信号

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
    //输入你想写入的内容 
  
    while (1)
    {
        while (!PAK_Q.empty())
        {
            my_mutex.lock();
            PAK_INFO PACKAGE = PAK_Q.front();    //从队列取消息
            PAK_Q.pop();
            my_mutex.unlock();
          

            const unsigned char* data_addr;//最终求出有效载荷的地址

                /***************************************************************************************/
                /*************************************ETHERNET层****************************************/
                /***************************************************************************************/
            const unsigned char* ether_head = PACKAGE.pak_data;
            const unsigned char* src_MAC;                                               //源MAC地址，6bytes
            const unsigned char* dst_MAC;                                               //目的MAC地址
            const unsigned char* ether_protocol;                                    //以太层上层协议类型，2bytes
            dst_MAC = ether_head;
            src_MAC = ether_head + 6;
            ether_protocol = ether_head + 12;


            /***************************************************************************************/
            /*************************************IPv4层****************************************/
            /***************************************************************************************/
            if (*ether_protocol == 0x08 && *(ether_protocol + 1) == 0x00)
            {
                const unsigned char* ip_head1 = ether_head + 14;                                                    //ip起始位置
                const unsigned char* src_ip1 = ip_head1 + 12;                                                       //源ip地址 4bytes
                const unsigned char* dst_ip1 = ip_head1 + 16;                                                       //目的ip地址
                const unsigned char* ip_protocol1 = ip_head1 + 9;                                                   //上层协议 1bytes
                const unsigned char* ip_id = ip_head1 + 4;                                                          //报文id 2bytes
                int ip_head_len1 = unsigned  short(*(ip_head1) & 0x0F) * 4;                                         //ip头部长度
                const unsigned char* ip_len_addr1 = ip_head1 + 2;                                                   //ip报文总长度地址，2bytes
                unsigned  int ip_len1 = unsigned  int(*ip_len_addr1) * 256 + unsigned  int(*(ip_len_addr1 + 1));    //ip报文总长度
               
                int total_len = PACKAGE.pak_header->caplen;


                /***************************************************************************************/
                /*************************************UDP层*********************************************/
                /***************************************************************************************/
                if (*ip_protocol1 == 0x11)
                {

                    const unsigned char* udp_head1 = ip_head1 + ip_head_len1;                         //UDP层起始位置
                    const unsigned char* src_udp_port1 = udp_head1;                                   //UDP层源端口地址
                    const unsigned char* dst_udp_port2 = udp_head1 + 2;                               //UDP层目的端口地址

                    int SUP1_DEC = unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1));
                    int DUP1_DEC = unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1));

                    //L2TP分析，检查接下来的数据是否是L2TP协议
                    const unsigned char* l2tp_head = udp_head1 + 8;                         //L2TP层起始位置
                    int l2tp_len = 6;                                                       //l2tp头部长度，需要具体计算，初始为6
                    unsigned short l2tp_version = unsigned short(*(l2tp_head + 1));         //l2tp版本
                    bool T, L, S, O, P;                                                     //l2tp控制位
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

                    if (T && (!L || !S || O || P))                //控制报文L 1,ver 2，否则不是L2TP报文;
                    {
               
                        continue;
                    }

                    if (l2tp_control[5] || l2tp_control[4] || l2tp_control[2] || l2tp_version_bit[7] || l2tp_version_bit[6] || l2tp_version_bit[5] || l2tp_version_bit[4])   //填充位必然是0，否则不是L2TP报文
                    {
                        continue;
                    }

                    BOOL FLAG1, FLAG2, FLAG3, FLAG4;
                    FLAG1 = cmp_bytes(src_ip1, src_ip, 4) || cmp_bytes(src_ip, default_ip, 4);
                    FLAG2 = cmp_bytes(dst_ip1, dst_ip, 4) || cmp_bytes(dst_ip, default_ip, 4);

                    if (T)              //如果是L2TP控制报文 到此为止
                    {
                        if (!OPT)
                        {
                            pack_num++;

                            cout << endl;
                           
                            cout << endl;
                            //file << "\n\n";
                            cout << pack_num << "." << endl;
                            cout << "<=======================这是一条分割线=========================>";
                            //print_bytes(ether_head, total_len);
                            cout << endl;
                            cout << endl;
                            cout << "ETHERNET LAYER：" << endl;
                            cout << "源MAC：";
                            print_mac(src_MAC);
                            cout << endl;
                            cout << "目的MAC：";
                            print_mac(dst_MAC);
                            cout << endl;
                            cout << endl;

                            cout << "FIRST IPV4 LAYER:" << endl;
                            cout << "源IP地址：";
                            print_ip(src_ip1);
                            cout << endl;
                            cout << "目的IP地址：";
                            print_ip(dst_ip1);
                            cout << endl;
                            cout << "ID：" << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                            cout << endl;
                            cout << endl;

                            cout << "FIRST UDP LAYER:" << endl;
                            cout << "源端口：" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                            cout << endl;
                            cout << "目的端口：" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                            cout << endl;
                            cout << endl;

                            cout << "L2TP_ControlMessage 报文" << endl;
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
                                
                                cout << "<=======================这是一条分割线=========================>";
                                //print_bytes(ether_head, total_len);
                                cout << endl;
                                cout << endl;
                                cout << "ETHERNET LAYER：" << endl;
                                cout << "源MAC：";
                                print_mac(src_MAC);
                                cout << endl;
                                cout << "目的MAC：";
                                print_mac(dst_MAC);
                                cout << endl;
                                cout << endl;

                                cout << "FIRST IPV4 LAYER:" << endl;
                                cout << "源IP地址：";
                                print_ip(src_ip1);
                                cout << endl;
                                cout << "目的IP地址：";
                                print_ip(dst_ip1);
                                cout << endl;
                                cout << "ID：" << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                cout << endl;
                                cout << endl;

                                cout << "FIRST UDP LAYER:" << endl;
                                cout << "源端口：" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                cout << endl;
                                cout << "目的端口：" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                cout << endl;
                                cout << endl;

                                cout << "L2TP_ControlMessage 报文" << endl;
                                cout << endl;
                            }
                        }
                    }


                    /***************************************************************************************/
                    /*************************************L2TP层****************************************/
                    /***************************************************************************************/
                    //根据控制位，开始求L2TP报文长度
                    if (L)
                        l2tp_len += 2;
                    if (S)
                        l2tp_len += 4;
                    if (O)
                        l2tp_len += 2;

                    const unsigned char* l2tp_tunel;                //L2TP层Tunel起始位置
                    const unsigned char* l2tp_session;               //L2TP层session起始位置
                    if (L)
                    {
                        l2tp_tunel = l2tp_head + 4;                 //L2TP层Tunel起始位置
                        l2tp_session = l2tp_head + 6;                //L2TP层session起始位置
                    }
                    else
                    {
                        l2tp_tunel = l2tp_head + 2;                 //L2TP层Tunel起始位置
                        l2tp_session = l2tp_head + 4;               //L2TP层session起始位置
                    }
                    
                    int l2tp_tunel_id = unsigned int(*l2tp_tunel) * 256 + unsigned int(*(l2tp_tunel + 1));
                    int l2tp_session_id = unsigned int(*l2tp_session) * 256 + unsigned int(*(l2tp_session + 1));


                /***************************************************************************************/
                /*************************************PPP层*********************************************/
                /***************************************************************************************/
                    const unsigned char* ppp_head = l2tp_head + l2tp_len; //ppp起始地址
                    const unsigned char* ppp_addr = ppp_head;//ppp地址位，1bytes
                    const unsigned char* ppp_control = ppp_head + 1;//ppp控制位，1bytes


                    //ppp_flag，ppp_addr，ppp_control共同确定是否是ppp报文  fff 03

                    if (*ppp_addr != 0xFF || *ppp_control != 0x03)
                    {
                        
                        continue;
                    }


                    BOOL SMAC, DMAC, SIP, DIP, SPORT, DPORT;       //过滤控制位

                    if (!OPT)
                    {
                        pack_num++;
                        cout << endl;    cout << endl;
                        cout << pack_num << "." << endl;
                        cout << "<=======================这是一条分割线=========================>";
                        //print_bytes(ether_head, total_len);
                        cout << endl;
                        cout << endl;
                        cout << "ETHERNET LAYER：" << endl;
                        cout << "源MAC：";
                        print_mac(src_MAC);
                        cout << endl;
                        cout << "目的MAC：";
                        print_mac(dst_MAC);
                        cout << endl;
                        cout << endl;

                        cout << "FIRST IPV4 LAYER:" << endl;
                        cout << "源IP地址：";
                        print_ip(src_ip1);
                        cout << endl;
                        cout << "目的IP地址：";
                        print_ip(dst_ip1);
                        cout << endl;
                        cout << "ID：";
                        cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                        cout << endl;
                        cout << endl;


                        cout << "FIRST UDP LAYER:" << endl;
                        cout << "源端口：" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                        cout << endl;
                        cout << "目的端口：" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                        cout << endl;
                        cout << endl;

                        cout << "*L2TP LAYER:" << endl;
                        cout << "Tunel_ID：" << l2tp_tunel_id << endl;
                        cout << "Session_ID：" << l2tp_session_id << endl;

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
                    /*************************************PPP IPv4层****************************************/
                    /***************************************************************************************/
                    const unsigned char* ppp_protocol1 = ppp_head + 2;              //ppp上层协议标志1，1bytes
                    const unsigned char* ppp_protocol2 = ppp_head + 3;              //ppp上层协议标志2，1bytes
                    //IP层2分析
                    if (*ppp_protocol1 == 0x00 && *ppp_protocol2 == 0x21) //ip协议
                    {
                        //IP层2
                        const unsigned char* ip_head2 = ppp_head + 4;                                                            //ip起始位置
                        const unsigned char* src_ip2 = ip_head2 + 12;                                                           //源ip地址，4bytes
                        const unsigned char* dst_ip2 = ip_head2 + 16;                                                            //目的ip地址
                        const unsigned char* ip_protocol2 = ip_head2 + 9;                                                       //上层协议 1bytes
                        const unsigned char* ip_id2 = ip_head2 + 4;                                                             //报文id 2bytes
                        const unsigned char* ip_len_addr2 = ip_head2 + 2;                                                        //ip报文总长度地址，2bytes
                        unsigned  int ip_head_len2 = unsigned  int(*(ip_head2) & 0x0F) * 4;                                     //ip头部长度
                        unsigned  int ip_len2 = unsigned  int(*ip_len_addr2) * 256 + unsigned  int(*(ip_len_addr2 + 1));        // ip报文总长度

                        if (!OPT)
                        {
                            cout << "SECOND IPV4 LAYER:" << endl;
                            cout << "源IP地址：";
                            print_ip(src_ip2);
                            cout << endl;
                            cout << "目的IP地址：";
                            print_ip(dst_ip2);
                            cout << endl;
                            cout << "ID：";
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

                        //最里层数据UDP/TCP

                        const unsigned char* inner_head = ip_head2 + ip_head_len2;  
                        unsigned  int inner_len = ip_len2 - ip_head_len2;                       //最里层报文长度
                        const unsigned char* SP2 = inner_head;                                  //UDP\TCP层源端口地址
                        const unsigned char* DP2 = inner_head + 2;                              //UDP\TCP层目的端口地址
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
                                cout << "源端口：" << (unsigned int(*SP2) * 256 + unsigned int(*(SP2 + 1)));
                                cout << endl;
                                cout << "目的端口：" << (unsigned int(*DP2) * 256 + unsigned int(*(DP2 + 1)));
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
                                    cout << "<=======================这是一条分割线=========================>";
                                   
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "ETHERNET LAYER：" << endl;
                                    cout << "源MAC：";
                                    print_mac(src_MAC);
                                    cout << endl;
                                    cout << "目的MAC：";
                                    print_mac(dst_MAC);
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "FIRST IPV4 LAYER:" << endl;
                                    cout << "源IP地址：";
                                    print_ip(src_ip1);
                                    cout << endl;
                                    cout << "目的IP地址：";
                                    print_ip(dst_ip1);
                                    cout << endl;
                                    cout << "ID：";
                                    cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "FIRST UDP LAYER:" << endl;
                                    cout << "源端口：" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                    cout << endl;
                                    cout << "目的端口：" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "*L2TP LAYER:" << endl;
                                    cout << "Tunel_ID：" << l2tp_tunel_id << endl;
                                    cout << "Session_ID：" << l2tp_session_id << endl;

                                    cout << endl;

                                    /***********************/
                                    cout << "PPP LAYER:" << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "SECOND IPV4 LAYER:" << endl;
                                    cout << "源IP地址：";
                                    print_ip(src_ip2);
                                    cout << endl;
                                    cout << "目的IP地址：";
                                    print_ip(dst_ip2);
                                    cout << endl;
                                    cout << "ID：";
                                    cout << (unsigned short(*ip_id2) * 256 + unsigned short(*(ip_id2 + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "SECOND UDP LAYER:" << endl;
                                    cout << "源端口：" << (unsigned int(*SP2) * 256 + unsigned int(*(SP2 + 1)));
                                    cout << endl;
                                    cout << "目的端口：" << (unsigned int(*DP2) * 256 + unsigned int(*(DP2 + 1)));
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
                                cout << "源端口：" << (unsigned int(*SP2) * 256 + unsigned int(*(SP2 + 1)));
                                cout << endl;
                                cout << "目的端口：" << (unsigned int(*DP2) * 256 + unsigned int(*(DP2 + 1)));
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
                                    cout << "<=======================这是一条分割线=========================>";
                                    
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "ETHERNET LAYER：" << endl;
                                    cout << "源MAC：";
                                    print_mac(src_MAC);
                                    cout << endl;
                                    cout << "目的MAC：";
                                    print_mac(dst_MAC);
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "FIRST IPV4 LAYER:" << endl;
                                    cout << "源IP地址：";
                                    print_ip(src_ip1);
                                    cout << endl;
                                    cout << "目的IP地址：";
                                    print_ip(dst_ip1);
                                    cout << endl;
                                    cout << "ID：";
                                    cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "FIRST UDP LAYER:" << endl;
                                    cout << "源端口：" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                    cout << endl;
                                    cout << "目的端口：" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "*L2TP LAYER:" << endl;
                                    cout << "Tunel_ID：" << l2tp_tunel_id << endl;
                                    cout << "Session_ID：" << l2tp_session_id << endl;

                                    cout << endl;

                                    /***********************/
                                    cout << "PPP LAYER:" << endl;
                                    cout << endl;
                                    /***********************/
                                    cout << "SECOND IPV4 LAYER:" << endl;
                                    cout << "源IP地址：";
                                    print_ip(src_ip2);
                                    cout << endl;
                                    cout << "目的IP地址：";
                                    print_ip(dst_ip2);
                                    cout << endl;
                                    cout << "ID：";
                                    cout << (unsigned short(*ip_id2) * 256 + unsigned short(*(ip_id2 + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "SECOND UDP LAYER:" << endl;
                                    cout << "源端口：" << (unsigned int(*SP2) * 256 + unsigned int(*(SP2 + 1)));
                                    cout << endl;
                                    cout << "目的端口：" << (unsigned int(*DP2) * 256 + unsigned int(*(DP2 + 1)));
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
                                cout << "ICMP报文";
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
                                    cout << "<=======================这是一条分割线=========================>";
                                    cout << endl;
                                    cout << endl;
                                    cout << "ETHERNET LAYER：" << endl;
                                    cout << "源MAC：";
                                    print_mac(src_MAC);
                                    cout << endl;
                                    cout << "目的MAC：";
                                    print_mac(dst_MAC);
                                    cout << endl;
                                    cout << endl;
                                    /***********************/

                                    cout << "FIRST IPV4 LAYER:" << endl;
                                    cout << "源IP地址：";
                                    print_ip(src_ip1);
                                    cout << endl;
                                    cout << "目的IP地址：";
                                    print_ip(dst_ip1);
                                    cout << endl;
                                    cout << "ID：";
                                    cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "FIRST UDP LAYER:" << endl;
                                    cout << "源端口：" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                    cout << endl;
                                    cout << "目的端口：" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                    cout << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "*L2TP LAYER:" << endl;
                                    cout << "Tunel_ID：" << l2tp_tunel_id << endl;
                                    cout << "Session_ID：" << l2tp_session_id << endl;

                                    cout << endl;
                                    /***********************/
                                    cout << "PPP LAYER:" << endl;
                                    cout << endl;

                                    /***********************/
                                    cout << "SECOND IPV4 LAYER:" << endl;
                                    cout << "源IP地址：";
                                    print_ip(src_ip2);
                                    cout << endl;
                                    cout << "目的IP地址：";
                                    print_ip(dst_ip2);
                                    cout << endl;
                                    cout << "ID：";
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
                            cout << "LCP报文" << endl;
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
                                cout << "<=======================这是一条分割线=========================>";
                                //print_bytes(ether_head, total_len);
                                cout << endl;
                                cout << endl;
                                /***********************/
                                cout << "ETHERNET LAYER：" << endl;
                                cout << "源MAC：";
                                print_mac(src_MAC);
                                cout << endl;
                                cout << "目的MAC：";
                                print_mac(dst_MAC);
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "FIRST IPV4 LAYER:" << endl;
                                cout << "源IP地址：";
                                print_ip(src_ip1);
                                cout << endl;
                                cout << "目的IP地址：";
                                print_ip(dst_ip1);
                                cout << endl;
                                cout << "ID：";
                                cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "FIRST UDP LAYER:" << endl;
                                cout << "源端口：" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                cout << endl;
                                cout << "目的端口：" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "*L2TP LAYER:" << endl;
                                cout << "Tunel_ID：" << l2tp_tunel_id << endl;
                                cout << "Session_ID：" << l2tp_session_id << endl;

                                /***********************/
                                cout << endl;
                                cout << "PPP LAYER:" << endl;
                                cout << endl;
                                cout << "LCP报文" << endl;
                            }
                        }
                    }//end of lcp
                    else if (*ppp_protocol1 == 0xC2 && *ppp_protocol2 == 0x23)   //CHAP
                    {
                        if (!OPT)
                        {
                            cout << "CHAP报文" << endl;
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
                                cout << "<=======================这是一条分割线=========================>";
                                //print_bytes(ether_head, total_len);
                                cout << endl;
                                cout << endl;
                                /***********************/
                                cout << "ETHERNET LAYER：" << endl;
                                cout << "源MAC：";
                                print_mac(src_MAC);
                                cout << endl;
                                cout << "目的MAC：";
                                print_mac(dst_MAC);
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "FIRST IPV4 LAYER:" << endl;
                                cout << "源IP地址：";
                                print_ip(src_ip1);
                                cout << endl;
                                cout << "目的IP地址：";
                                print_ip(dst_ip1);
                                cout << endl;
                                cout << "ID：";
                                cout << (unsigned int(*ip_id) * 256 + unsigned int(*(ip_id + 1)));
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "FIRST UDP LAYER:" << endl;
                                cout << "源端口：" << (unsigned int(*src_udp_port1) * 256 + unsigned int(*(src_udp_port1 + 1)));
                                cout << endl;
                                cout << "目的端口：" << (unsigned int(*dst_udp_port2) * 256 + unsigned int(*(dst_udp_port2 + 1)));
                                cout << endl;
                                cout << endl;

                                /***********************/
                                cout << "*L2TP LAYER:" << endl;
                                cout << "Tunel_ID：" << l2tp_tunel_id << endl;
                                cout << "Session_ID：" << l2tp_session_id << endl;

                                cout << endl;

                                /***********************/
                                cout << "PPP LAYER:" << endl;
                                cout << endl;
                                cout << "CHAP报文" << endl;
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
    * pcap_if_t：typedef struct pcap_if pcap_if_t 保存网卡基本信息的类型。通常用指针来使用，pcap_if_t *my_devs
    * struct pcap_if
    * {
    * struct pcap_if *next;             //指向下一个网卡
    * char *name;                       //网卡的标识符，唯一识别一个网卡
    * char *description;                //用来描述网卡
    * struct pcap_addr*address;         //网卡的地址，包括IP地址，网络掩码，广播地址等，类型中的成员变量在后面会写到
    * bpf_u_int32 flags;                //接口标志
    * 
    */
    pcap_if_t* my_devs, * tmp_devs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 找出所有网卡信息
    if (pcap_findalldevs(&my_devs, errbuf) == -1)   //错误处理
    {
        fprintf(stderr, "Error in pcap_findalldevs:%s\n", errbuf);
        exit(1);
    }

    //  打印所有网卡信息
    int i = 0;
    for (tmp_devs = my_devs; tmp_devs; tmp_devs = tmp_devs->next)
    {
        printf("%d : %s", ++i, tmp_devs->name);
        if (tmp_devs->description)
            printf(" (%s)\n", tmp_devs->description);
        else
            printf(" (No description available)\n");
    }


    //打开网卡
    int inum;
    printf("\n<=====请选择您要监听的网卡 (1-%d)=====>:\t", i);
    scanf("%d", &inum);               //输入要选择打开的网卡号

    for (tmp_devs = my_devs, i = 0; i < inum - 1; tmp_devs = tmp_devs->next, i++);               //找到选择的网卡

    dev_handle = pcap_open_live(tmp_devs->name, 65536, 0, 1000, errbuf);
    pcap_freealldevs(my_devs);

    cout << endl;
    cout << "<====是否进行ip/端口过滤，输入1(是)，0(否)===>" << endl;
    cin >> OPT;

    if (OPT)
    {


        cout << "请输入过滤的src ip（0.0.0.0表示不过滤）：" << endl;     //10进制
        for (int i = 0; i < 4; i++)
        {
            if (i < 3)
                scanf("%hhu.", src_ip + i);
            else
                scanf("%hhu", src_ip + i);
            
        }
        cout << "请输入过滤的dst ip（0.0.0.0表示不过滤）：" << endl;     //10进制
        for (int i = 0; i < 4; i++)
        {
            if (i < 3)
                scanf("%hhu.", dst_ip + i);
            else
                scanf("%hhu", dst_ip + i);

        }


        cout << "请输入过滤src端口（0表示不过滤）：" << endl;
        cin >> src_port;

        cout << "请输入过滤dst端口（0表示不过滤）：" << endl;
        cin >> dst_port;
       
        

        cout << "正在监听中... 请等待\n";
    }
    else
        cout << "正在监听中... 请等待\n";


    /******
    *  用两个进程
    *  一个用来监听，一个用来分析这样就可以减少丢包
    *****/
    thread  _listen_(packet_listen);          
    thread  _capture_(packet_capture);              

    _listen_.join();
    _capture_.join();


    return 0;
}


