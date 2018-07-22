#include <stdio.h>
#include <stdlib.h>

void do_nothing() {
	int *xyz = (int*)malloc(2);
}

int main(int argc, char* argv[]) {
	free(NULL);

	do_nothing();

	char *A = (char*)malloc(128 * sizeof(char));
	char *B = (char*)malloc(128 * sizeof(char));
	char *C = (char*)malloc(128 * sizeof(char));

	free(A);
	free(C);

	if (argc != 2)
		do_nothing();
	else
		free(C);

	puts("done");
	return 0;
}
