/*
 * zombie: Test program to spawn a two zombie sub-processes.
 */
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_SLEEP_COUNT 3600 /* In seconds. */

void count_down(int16_t n) {
    while (--n >= 0)
        sleep(1);
}

int main(void) {
    if (fork() == 0)
        return 0;

    if (fork() == 0)
        return 0;

    count_down(MAX_SLEEP_COUNT + 1);

    /* Wait for all children. */
    wait(NULL);
    wait(NULL);

    return 0;
}
