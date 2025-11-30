#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


int return_random(int max) {
    return rand() % max + 1 ;
}

int main() {
    srand(time(NULL));
    for (int i = 0; i < 20; i++) {
        int delay = 10 - 5;
        int random = return_random(delay);
        printf("%d\n", 5 + random - 1);
    }
}
