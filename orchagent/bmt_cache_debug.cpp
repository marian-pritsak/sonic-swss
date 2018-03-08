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
#include <cstring>
#include <deque>

#include "bmt_common.h"
#include "logger.h"
#include "bmt_orch_constants.h"

extern global_config_t g;
pthread_t debug_thread;
int sock = 0;

template<typename O> void split(const std::string &s, char delim, O result) {
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (getline(ss, item, delim)) {
        if (!item.empty()) *(result++) = item;
    }
}

std::deque<std::string> split(const std::string &s, char delim) {
    std::deque<std::string> elems;
    split(s, delim, back_inserter(elems));
    return elems;
}

/**
 * Simple command mapping:
 * INPUT    CFG     OUTPUT
 * exit
 * scan
 * flush
 *
 */
static const char * cmd_list = "??? Try - status, flush, pause, resume, window, ithresh, ethresh, evac-stop, insert-stop";

void dispatch(std::string &input, global_config_t* cfg, std::ostringstream &stream) {
    try {
        std::deque<std::string> input_args;
        input_args = split(input,' ');
        if (input_args.empty()) {
            stream << input << cmd_list;
        }
        else {
            std::string first = input_args.front();
            input_args.pop_front();
            if (!first.compare("evac-stop")) {
                cfg->exitFlag = true;
                stream << "Exiting evacuator thread";
            }
            else if (!first.compare("insert-stop")) {
                cfg->scanDpdkPort = true;
                stream << "Exiting inserter thread";
            }
            else if (!first.compare("flush")) {
                cfg->flushCache = true;
                stream << "Flushing the cache";
            }
            else if (!first.compare("pause")) {
                cfg->pauseCacheInsertion = true;
                stream << "Insertion paused";
            }
            else if (!first.compare("resume")) {
                cfg->pauseCacheInsertion = false;
                stream << "Insertion resumed";
            }
            else if (!first.compare("window")) {
                if (!input_args.empty()) {
                    std::string value = input_args.front();
                    cfg->insertionWindowSize = (uint32_t) stoul(value,nullptr,0);
                    input_args.pop_front();
                }
                stream << "Insertion window size is " << cfg->insertionWindowSize;
            }
            else if (!first.compare("ithresh")) {
                if (!input_args.empty()) {
                    std::string value = input_args.front();
                    cfg->insertionThreshold = (uint32_t) stoul(value,nullptr,0);
                    input_args.pop_front();
                }
                stream << "Insertion threshold is " << cfg->insertionThreshold;

            }
            else if (!first.compare("ethresh")) {
                if (!input_args.empty()) {
                    std::string value = input_args.front();
                    cfg->evacuationThreshold = (uint32_t) stoul(value,nullptr,0);
                    input_args.pop_front();
                }
                stream << "Evacuation threshold is " << cfg->evacuationThreshold;
            }
            else if (!first.compare("status") || !input.compare("s")) {
                stream << "sampler init status " << cfg->sampler_init_status << std::endl;
                stream << "inserter is " << (cfg->pauseCacheInsertion ? "paused" : "running") << std::endl;
                stream << "insert window size " << cfg->insertionWindowSize << std::endl;
                stream << "insert threshold " << cfg->insertionThreshold << std::endl;
                stream << "evacuation threshold " << cfg->evacuationThreshold << std::endl;
                stream << "cache inserts " << cfg->cacheInsertCount
                    << ", skip " << cfg->cacheInsertSkip
                    << ", remove " << cfg->cacheRemoveCount << std::endl;
                stream << "entry counter ";
                for (int i = 0; i <  VHOST_TABLE_SIZE; i++) {
                    stream << "#" << i << ": "<< cfg->entryCounters[i] << ", ";
                }
                stream << std::endl;
                stream << "flushCache " << cfg->flushCache << std::endl;
                stream << "exitFlag " << cfg->exitFlag << std::endl;
                stream << "scanDpdkPort " << cfg->scanDpdkPort << std::endl;
            }
            else {
                stream << input << cmd_list;
            }
        }
    }
    catch (const std::exception &e) {
        stream << "Invalid command \"" << input << "\"" << ": " << e.what() << std::endl;
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

