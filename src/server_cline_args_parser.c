#include "server_cline_args_parser.h"

server_args_ptr cline_args;


server_args_ptr parse_cline_arguments(int argc, const char *argv[]) {

    int optChar;

    while((optChar = getopt(argc, argv, ":a:p:v:")) != -1){
        switch(optChar){
            case 'a':
                print("entre a la opcion a");
                
        }
    }   
}