#ifndef RANDOM_H
#define RANDOM_H 1
typedef int *callback_random(char *random,int len); 
void set_callback(callback_random *cb);
int genrate_random(char *random,int len); 
#endif

