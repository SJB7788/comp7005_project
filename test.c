#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char test[128] = "1,Hello";
    strtok(test, ",");
    printf("%s\n", test);
}
