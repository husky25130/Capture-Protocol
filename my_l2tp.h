//#pragma once
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

#include "pcap.h"
#include <Winsock2.h>

using namespace std;
/*
 *   |-------------------|
 *   |    Ethernet II    |   eth_header
 *   |-------------------|
 *   |       IPv4        |   ip_header
 *   |-------------------|
 *   |        UDP        |   udp_header
 *   |-------------------|
 *   |       L2TP        |   l2tp_header if control, end
 *   |-------------------|
 *   |       PPP         |   
 *   |-------------------|
 *   |       IPv4        |
 *   |-------------------|
 *   |      Payload      |  (TCP/UDP)
 *   |-------------------|
 *
 */

struct PAK_INFO                         //数据包信息结构体
{
    u_char* pak_data;
    pcap_pkthdr* pak_header;
};


void print_mac(const unsigned char* pos);        //将指定地址后6字节数据以MAC地址的形式输出

void print_ip(const unsigned char* pos);				//将指定地址后4字节数据以ip地址的形式输出

void print_bytes(const unsigned char* pos, int length);	//将指定地址后length字节数据以16进制输出

BOOL cmp_bytes(const unsigned char* a, unsigned char* b, int len);  //数据报文比较

const unsigned char* get_datas(int protocol_type, const unsigned char* inner_head, unsigned  int inner_len);  //获取有效载荷，返回载荷地址
