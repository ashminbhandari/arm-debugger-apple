#include <stdio.h>
#include <unistd.h>

int main()
{
    int tracked_variable = 0;
    sleep(20);
    for (int i = 0; i < 100000; i++)
    {
        tracked_variable++;
        printf("Tracked variable: %d\n", tracked_variable);
    }
    return 0;
}