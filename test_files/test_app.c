#include <stdio.h>

void test_function()
{
    char buffer[100];
    printf("Enter your name: ");
    scanf("%s", buffer);
    printf("Hello, %s!\n", buffer);
}

int main()
{
    test_function();
    return 0;
}