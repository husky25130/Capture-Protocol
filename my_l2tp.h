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

struct PAK_INFO                         //���ݰ���Ϣ�ṹ��
{
    u_char* pak_data;
    pcap_pkthdr* pak_header;
};


void print_mac(const unsigned char* pos);        //��ָ����ַ��6�ֽ�������MAC��ַ����ʽ���

void print_ip(const unsigned char* pos);				//��ָ����ַ��4�ֽ�������ip��ַ����ʽ���

void print_bytes(const unsigned char* pos, int length);	//��ָ����ַ��length�ֽ�������16�������

BOOL cmp_bytes(const unsigned char* a, unsigned char* b, int len);  //���ݱ��ıȽ�

const unsigned char* get_datas(int protocol_type, const unsigned char* inner_head, unsigned  int inner_len);  //��ȡ��Ч�غɣ������غɵ�ַ
