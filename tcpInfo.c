#include <string.h>
#include "tcpInfo.h"
#define OID_CODE ".1.3.6.1.2.1.6.13"

// Parses SNMP message to obtain remote address, remote port and local port
void parseTCP(char *src, char *address, char *port, char *localPort){
    int it=0, count=0;
    while(count < 5){
        if(src[it] == '.')
            count++;
        it++;
    }
    int it1=0;
    while(count < 6){
        if(src[it] == '.')
            count++;
        else
            localPort[it1] = src[it];
        it++;
        it1++;
    }
    localPort[it1-1] = '\0';
    it1=0;
    while(count < 10){
        if(src[it] == '.')
            count++;
        address[it1] = src[it];
        it++;
        it1++;
    }
    address[it1-1] = '\0';
    it1=0;
    while(src[it] >= '0' && src[it] <= '9'){
        port[it1] = src[it];
        it++;
        it1++;
    }
    port[it1] = '\0';
}

node* tcpInfo(netsnmp_session *ss){
    netsnmp_pdu *pdu, *response;
    oid OID[MAX_OID_LEN];
    size_t OID_len;
    netsnmp_variable_list *vars;

    pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
    pdu->max_repetitions = INT32_MAX;
    pdu->non_repeaters = 0;
    OID_len = MAX_OID_LEN;
    if (!snmp_parse_oid(OID_CODE, OID, &OID_len)) {
      snmp_perror(OID_CODE);
      exit(1);
    }

    snmp_add_null_var(pdu, OID, OID_len);
    int status = snmp_synch_response(ss, pdu, &response);
    node *root = malloc(sizeof(node)), *currNode;
    root->address = NULL;
    root->next = NULL;
    char aux = -1;
    if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){

        for(vars = response->variables; vars; vars = vars->next_variable){
            char varName[256], *varValue = malloc(256);
            snprint_variable(varName, 256, vars->name, vars->name_length, vars);
            snprint_value(varValue, 256, vars->name, vars->name_length, vars);
            if(strstr(varName, "tcpConnState") && *vars->val.integer == 5){
                if(aux == -1){
                    currNode = root;
                    aux = 0;
                }else{
                    currNode->next = malloc(sizeof(node));
                    currNode = currNode->next;
                    currNode->next = NULL;
                }
                char *address=malloc(256), *port=malloc(256), *localPort=malloc(256);
                parseTCP(varName, address, port, localPort);
                currNode->address = address;
                currNode->port = atoi(port);
                currNode->localPort = atoi(localPort);
            }
        }

    }else{
        if(status == STAT_SUCCESS)
            fprintf(stderr, "Error in packet\nReason: %s\n",
                snmp_errstring(response->errstat));
            else if(status == STAT_TIMEOUT)
                fprintf(stderr, "Timeout: No response\n");
            else
                snmp_sess_perror("Error:", ss);
    }

    if(response)
        snmp_free_pdu(response);

    return root;
}