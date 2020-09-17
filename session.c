#include "session.h"

netsnmp_session* init_session(char *app, char *host, char *community){
    netsnmp_session session, *ss;
    init_snmp(app);
    snmp_sess_init(&session);
    session.peername = host;
    session.version = SNMP_VERSION_2c;
    session.community = community;
    session.community_len = strlen(session.community);
    ss = snmp_open(&session);
    if(!ss){
        snmp_sess_perror("ack", &session);
        exit(1);
    }
    return ss;
}