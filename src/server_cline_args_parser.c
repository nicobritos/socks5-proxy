#include "server_cline_args_parser.h"

server_args_ptr cline_args;


server_args_ptr parse_cline_arguments(int argc, const char *argv[]) {
    int optchar;

    while((optchar = getopt(argc, argv, ":a:p:v:")) != -1){
        switch(optchar){
            case 'h':
                print_options();
                exit(0);
            case 'a':
                printf("entre a la opcion a\n");
                cline_args->address = malloc(strlen(optarg) + 1);
                memcpy(cline_args->address, optarg, strlen(optarg) + 1);
                break;
            case 'p':
                printf("entre a la opcion p\n");
                cline_args->port = parse_port(optarg);
                break;
            case '?':
                error(optopt);
                exit(1);
            default:
                exit(1);
        }
    }   
}

static error(int c){
    if(c == 'a' || c == 'p'){
        fprintf(stderr, "Error: Option %c must be followed by an argument, please try again\n",c);
    } else{
        fprintf(stderr, "Error: %c is does not exist, please enter a valid option\n",c);
    }
}

static uint16_t parse_port(const char *port){
    int p=0;
    
    while(isdigit(*port)){
        p = p * 10 + (*port - '0');
        port++;
    }
    
    //el port no representaba un puerto valido
    if(*port != '\0' && !isdigit(*port)){
        fprintf(stderr,"Error: Invalid port, -p argument cannot contain %s\n",*port);
        exit(1);
    }

    return (uint16_t) p;
}

static vois print_options(){
    printf("Options:\n");
    printf("\t-%c\tShow valid options\n",'h');
    printf("\t-%c\tSet address\n",'a');
    printf("\t-%c\tSet port\n",'p');
}