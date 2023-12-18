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

void print_mac(const unsigned char* pos)        //将指定地址后6字节数据以MAC地址的形式输出
{
    for (int i = 0; i < 6; i++)
    {
        unsigned short data = *(pos + i);
        if (i < 5)
        {
            if (data <= 15)
                cout << '0' << hex << data << ':';
            else
                cout << hex << data << ':';
        }
        else
        {
            if (data <= 15)
                cout << '0' << hex << data;
            else
                cout << hex << data;
        }
    }
}

void print_ip(const unsigned char* pos)
{
    for (int i = 0; i < 4; i++)
    {
        unsigned short data = *(pos + i);
        if (i < 3)
            cout << dec << data << '.';
        else
            cout << dec << data;
    }
}

void print_bytes(const unsigned char* pos, int length)
{
    int count = 0;
    for (int i = 0; i < length; i++)
    {

        if (isgraph(*(pos + i)) || *(pos + i) == ' ')
        {
            cout << *(pos + i);
        }
        count++;
    }
}

BOOL cmp_bytes(const unsigned char* a, unsigned char* b, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (*(a + i) != *(b + i))
        {
            return FALSE;
        }
    }
    return TRUE;
}

const unsigned char* get_datas(int protocol_type, const unsigned char* inner_head, unsigned  int inner_len) 
{
    if (protocol_type == 0x06)         //tcp
    {
        cout << "有效载荷：" << endl;
        unsigned int head_len = unsigned int(*(inner_head + 12)) / 4;
        unsigned int data_len = inner_len - head_len;
        const unsigned char* data_head = inner_head + head_len;
        print_bytes(data_head, data_len);
        cout << endl;
        cout << endl;
        return data_head;
    }
    else if (protocol_type == 0x11)          //udp
    {
        cout << "有效载荷：" << endl;
        const unsigned char* data_head = inner_head + 8;
        unsigned int data_len = inner_len - 8;
        print_bytes(data_head, data_len);
        cout << endl;
        cout << endl;
        return data_head;
    }
       return NULL;
}

