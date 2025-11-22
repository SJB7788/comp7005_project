#include <stdio.h>
#include <stdlib.h>

int main() {
    char test[128];
    int seq = 0;

    snprintf(test, sizeof(test), "%d", seq);
    printf("%s\n", test);
}
