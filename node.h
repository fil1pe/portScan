#ifndef NODE_H
#define NODE_H

typedef struct nodeStruct {
    char *address;
    int port, localPort;
    struct nodeStruct *next;
} node;

#endif