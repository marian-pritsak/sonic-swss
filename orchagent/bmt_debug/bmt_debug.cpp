/*
 * bmt_debug.cpp
 *
 *  Created on: Mar 6, 2018
 *      Author: alan
 */
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <sstream>

#include <arpa/inet.h>
#if __APPLE__
#include <net/ethernet.h>
#else
#include <netinet/ether.h>
#include <netinet/in.h>
#endif
#include <sys/socket.h>


#define SERVER "127.0.0.1"
#define BUFLEN 2000  //Max length of buffer
#define DEBUG_PORT 50505   //The port on which to send data

  int sock{0};
  struct sockaddr_in si_other;

void do_debug()
{
    printf("Debug BMT client connecting on port %d\n", DEBUG_PORT);
    socklen_t slen=sizeof(si_other);
    std::string message;
    char buf[BUFLEN];

    if ( (sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        fprintf(stderr,"BMT debug error in socket()");
    }

    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(DEBUG_PORT);

    if (inet_aton(SERVER , &si_other.sin_addr) == 0) {
        fprintf(stderr,"BMT debug error in inet_aton()");
    }
    while(1)
    {
        printf("BMT> ");
        getline( std::cin, message );
        memcpy(buf, message.c_str(), message.length()+1);

        //send the message
        if (sendto(sock, buf, message.length(), 0 , (struct sockaddr*)&si_other, slen)==-1) {
            fprintf(stderr,"BMT debug error in sendto()");
        }
        // printf("Sent %s\n", buf);

        //receive a reply and print it
        //clear the buffer by filling null, it might have previously received data
        memset(buf,'\0', BUFLEN);
        //try to receive some data, this is a blocking call
        if (recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen) == -1) {
            fprintf(stderr,"BMT debug error in recvfrom()");
        }
        printf("%s\n", buf);
        //puts(buf);
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    std::cout << "BMT debug " << std::endl;
    do_debug();
    return 0;

}

