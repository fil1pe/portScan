#include <stdio.h>
#include <string.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "session.h"
#include "node.h"
#include "udpInfo.h"
#include "tcpInfo.h"

void fitAddress(node *list){
    node *root = list;
    int maxLen = 0;
    while(root && root->address){
        int len = strlen(root->address);
        if(len > maxLen)
            maxLen = len;
        root = root->next;
    }
    root = list;
    while(root && root->address){
        int i;
        for(i=strlen(root->address); i<maxLen; i++)
            root->address[i] = ' ';
        root->address[i] = '\0';
        root = root->next;
    }
}

int main(int argc, char *argv[]){
    char showUDP=0, showTCP=0, host[40];

    // Parses arguments
    strcpy(host, "127.0.0.1");
    for(int i=1; i<argc; i++){
        if(argv[i][0] == '-'){
            if(strcmp(&argv[i][1], "TCP") == 0)
                showTCP = 1;
            else if(strcmp(&argv[i][1], "UDP") == 0)
                showUDP = 1;
        } else
            strcpy(host, argv[i]);
    }
    if(!showUDP && !showTCP)
        showUDP = showTCP = 1;

    // Initializes SNMP session
    #if defined(COMM)
    netsnmp_session *ss = init_session("portScan", host, COMM);
    #else
    netsnmp_session *ss = init_session("portScan", host, "public");
    #endif

    // Shows UDP ports 
    if(showUDP){
        printf("\033[1mPorts used for UDP communication\033[0m\n");
        node *udpList = udpInfo(ss);
        fitAddress(udpList);
        if(udpList->address)
            while(udpList){
                printf("IP address: %s  Remote port: %05d\n",
                    udpList->address, udpList->port);
                udpList = udpList->next;
            }
        else
            printf("None\n");
    }

    // Shows TCP ports
    if(showTCP){
        printf("\033[1mTCP connections established\033[0m\n");
        node *tcpList = tcpInfo(ss);
        fitAddress(tcpList);
        if(tcpList->address)
            while(tcpList){
                printf("IP address: %s  Local port: %05d  Remote port: %05d\n",
                    tcpList->address, tcpList->localPort, tcpList->port);
                tcpList = tcpList->next;
            }
        else
            printf("None\n");
    }

    // Closes SNMP session
    snmp_close(ss);

    return 0;
}