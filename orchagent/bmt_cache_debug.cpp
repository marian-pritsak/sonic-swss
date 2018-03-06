#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/in.h>
#include <iostream>
#include <sstream>
#include <map>

#include "bmt_common.h"
#include "logger.h"
#include "bmt_common.h"

extern global_config_t g;
pthread_t debug_thread;
int sock = 0;

/**
 * Simple command mapping:
 * INPUT    CFG     OUTPUT
 * exit
 * scan
 * flush
 *
 */
void dispatch(std::string &input, global_config_t* cfg, std::ostringstream &stream) {
    (void)cfg;
    if (!input.compare("evac-stop")) {
        cfg->exitFlag = true;
        stream << "Exiting evacuator thread";
    }
    else if (!input.compare("insert-stop")) {
        cfg->scanDpdkPort = true;
        stream << "Exiting inserter thread";
    }
    else if (!input.compare("flush")) {
        cfg->flushCache = true;
        stream << "Flushing the cache";
    }
    else if (!input.compare("pause")) {
        cfg->pauseCacheInsertion = true;
        stream << "Insertion paused";
    }
    else if (!input.compare("resume")) {
        cfg->pauseCacheInsertion = false;
        stream << "Insertion resumed";
    }
    else if (!input.compare("status") || !input.compare("s")) {
        stream << "sampler init status " << cfg->sampler_init_status << std::endl;
        stream << "inserter is " << (cfg->pauseCacheInsertion ? "running" : "paused") << std::endl;
        stream << "cacheInsertCount " << cfg->cacheInsertCount << std::endl;
        stream << "cacheInsertSkip " << cfg->cacheInsertSkip << std::endl;
        stream << "cacheRemoveCount " << cfg->cacheRemoveCount << std::endl;
        stream << "flushCache " << cfg->flushCache << std::endl;
        stream << "exitFlag " << cfg->exitFlag << std::endl;
        stream << "scanDpdkPort " << cfg->scanDpdkPort << std::endl;
    }
    else {
        stream << input << "??? Try - status, flush, pause, resume, evac-stop, insert-stop";
    }
}

void* debug_listener(void * data)
{
    static const int BUFLEN = 2000;
    char buf[BUFLEN+1];
    struct sockaddr_in si_other;
    int slen = sizeof(si_other);
    ssize_t recv_len;
    global_config_t* cfg = (global_config_t*) data;
    std::string raw_input;
    printf("starting BMT debug listener thread\n");

    while(1)
    {
        fflush(stdout);
        memset(buf,'\0', BUFLEN);
        if ((recv_len = recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &si_other, (socklen_t *)&slen)) == -1) {
            SWSS_LOG_ERROR("BMT debug server recvfrom error");
        }
        printf("Received BMT command: \"%s\"\n" , buf);
        raw_input.clear();
        raw_input.assign(buf);
        std::ostringstream stream;
        dispatch(raw_input, cfg, stream);
        std::string str = stream.str();
        int len = (int)str.length()+1;
        if (len >= BUFLEN) {
            len = BUFLEN;
            memcpy(buf, str.c_str(), len-1);
            buf[BUFLEN] = '\0';
        }
        else {
            memcpy(buf, str.c_str(), len);
        }
        //now reply the client with the same data
        if (sendto(sock, buf, len, 0, (struct sockaddr*) &si_other, slen) == -1) {
            SWSS_LOG_ERROR("BMT debug server sendto error");
        }
        // printf("Sent response of %u bytes\n", len);
    }
    close(sock);
    return 0;
}

int start_server(global_config_t* cfg) {
    printf("Debug server thread started\n");
    return pthread_create(&debug_thread, NULL, debug_listener, cfg);
}

int stop_server() {
    printf("Debug server thread stopped\n");
    return pthread_cancel(debug_thread);
}

/**
 * A test UDP server connection, to pass back debug commands
 */
int bmt_cache_debug_init() {
    static int PORT = 50505;
    struct sockaddr_in si_me;

    //create a UDP socket
    if ((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        SWSS_LOG_ERROR("BMT debug server socket error");
    }

    // zero out the structure
    memset((char *) &si_me, 0, sizeof(si_me));

    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);

    //bind socket to port
    if( bind(sock , (struct sockaddr*)&si_me, sizeof(si_me) ) == -1) {
        SWSS_LOG_ERROR("BMT debug server bind error");
    }
    printf("Debug server initialized to port %i\n", PORT);

    start_server(&g);
    return 0;
}

int bmt_cache_debug_deinit() {
    shutdown(sock, 2);
    close(sock);
    stop_server();
    return 0;
}

