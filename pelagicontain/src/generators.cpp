/*
 *   Copyright (C) 2014 Pelagicore AB
 *   All rights reserved.
 */
#include <sys/time.h>
#include "ifaddrs.h"

#include "generators.h"

/*
 * Increase the counter and return an IP number based on that.
 */
std::string Generator::gen_ip_addr (const char *ip_addr_net)
{
    static int counter = 0;

    counter++;
    if (counter < 2 || counter > 254) {
        counter = 2;
    }

    char ip[20];
    snprintf(ip, sizeof(ip), "%s%d", ip_addr_net, counter);
    return std::string(ip);
}

std::string Generator::gen_ct_name()
{
    static const char alphanum[] = "abcdefghijklmnopqrstuvwxyz";
    struct timeval time;
    char name[10];

    gettimeofday(&time, NULL);
    srand((time.tv_sec * 1000) + (time.tv_usec / 1000));

    for (int i = 0; i < 9; i++) {
        name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    name[9] = '\0';
    return std::string(name);
}
