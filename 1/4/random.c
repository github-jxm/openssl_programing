#include <stdio.h>
#include <string.h>
#include "random.h"

callback_random *cb_rand=NULL;

static int default_random(char *random,int len )
{
	memset(random,0x01,len);
	return 0; 
}
void  set_callback(callback_random *cb)
{
	cb_rand=cb;
}

int  genrate_random(char *random,int len)
{
	if(cb_rand==NULL){
		return default_random(random,len);
	}else{
		return cb_rand(random,len);
	}
	return 0; 
}

/*
*/
