// BlockingAPI.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

void WaitFunction()
{
    for (int i = 0; i < 15; i++)
    {
        std::cout << "...sleep\n";
        Sleep(1);
    }
}

void InputFunction()
{
    std::cout << "Blocking on user input...\n";
    std::string test;
    std::cin >> test;
    WaitFunction();
}

int main()
{
    std::cout << "Starting wait\n";
    WaitFunction();
    std::cout << "...done\n";
    InputFunction();
    std::cout << "...done\n";
    WaitFunction();
    std::cout << "...done\n";
    return 0;
}

