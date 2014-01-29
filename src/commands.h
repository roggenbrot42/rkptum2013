#ifndef COMMANDS_H
#define COMMANDS_H

enum arg_t {NOARG = 0, INTARG = 1, INTLST = 2};

extern void listen(void);
extern void stop_listen(void);
extern struct command * add_command(char*,enum arg_t, void*); 

#endif
