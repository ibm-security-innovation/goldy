#ifndef _GOLDY_H_
#define _GOLDY_H_

#define GOLDY_VERSION "0.1"

struct instance {
    char* listen_host;
    char* listen_port;
    char* backend_host;
    char* backend_port;
    char* cert_file;
    char* private_key_file;
};

#endif
