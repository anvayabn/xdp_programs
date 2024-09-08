#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>


void usage(){
    printf("./xdp_loader <iface> <program_name>\n");
    return;
}

char *packet_type[] = { "MAL", "IPV4", "IPV6", "ARP", "OTHER"};

// struct log_entry{ 
//     __u64 timestamp;
//     __u32 proto_no;
// };
// void handle_event(void *ctx, int cpu, void *data, __u32 size) {
//     struct log_entry *log = (struct log_entry *)data;
    
//     write("[%l] : \n", log->timestamp);
// }
static int ifindex;
void cleanup_and_exit(int signo) {
    // Detach the XDP program
    if (bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        fprintf(stderr, "Failed to detach XDP program\n");
    } else {
        printf("XDP program detached from interface\n");
    }

    exit(0);  // Exit the program
}

/*
Loads the program 
takes 2 input - 1 : interfacename 2: program name
*/
int main(int argc, char **argv){ 

    if (argc < 3){
        usage(); 
        return 0; 
    }

    char *iface = argv[1];
    char *program_path = argv[2];

    printf("Loading %s to interface %s\n", program_path, iface);
    
    //open the  ebpf object file
    struct bpf_object *obj;
    obj = bpf_object__open_file(program_path, NULL); 
    if (libbpf_get_error(obj)){ 
        fprintf(stderr, "Failed to open file %s\n", program_path); 
        return 1;
    }

    // load to kernel
    int ret = bpf_object__load(obj);
    if (ret){ 
        fprintf(stderr, "Failed to load the program\n");
        return 1; 
    }

    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);


    //Attach the program to interface
    //get file descriptoer of the ebpof object
    ifindex = if_nametoindex(iface); 
    int xdp_prog_fd = bpf_program__fd(bpf_object__find_program_by_title(obj, "xdp_packet_counter_prog"));
    if (xdp_prog_fd < 0) {
        fprintf(stderr, "Failed to get file descriptor for XDP program\n");
        return 1;
    }

    // Attach the XDP program to the network interface
    if (bpf_set_link_xdp_fd(ifindex, xdp_prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        fprintf(stderr, "Failed to attach XDP program to interface\n");
        return 1;
    }

    // get the map file descriptor
    int count_map_fd = bpf_object__find_map_fd_by_name(obj, "counter_map"); 
    if (count_map_fd < 0){ 
        fprintf(stderr, "Failed to get countermap\n");
        return 1; 
    }
    // int log_map_fd = bpf_object__find_map_fd_by_name(obj, "log_map");
    // if (log_map_fd < 0){
    //     fprintf(stderr, "Failed to get log map fd\n"); 
    //     return 1; 
    // }
    // ring_buffer__new(log_map_fd, , )


    //open file
    // char filename[40];
    // struct tm *timenow;
    // time_t now = time(NULL);
    // timenow = gmtime(&now);
    // strftime(filename, sizeof(filename), "/home/anvayabn/universe/xdp_programs/log_files/%Y-%m-%d_%H:%M:%S_xdp.log", timenow);

    // int log_file_fd = open(filename, O_RDWR | O_CREAT);
    // if (log_file_fd < 0){ 
    //     fprintf(stderr, "Failed to create logfile %s\n", filename);
    //     //add cleanup function
    //     return 1;
    // }
    // printf("Created logfile %s\n", filename);
    printf("-----------------------------\n");


    while (1) { 
        __u32 key; 
        __u64 value;


        //lookup counter map and display the count on every  
        for (key = 1; key < 5; key++){ 
            if (bpf_map_lookup_elem(count_map_fd, &key, &value)){ 
                printf("%s: %llu packets\n", packet_type[key], value);
            }else{ 
                perror("bpf_map_lookup_error"); 
            }
        }

        printf("-----------------------------\n");

        // handle file logging from the ring buf
        sleep(2);
    }

    return 0; 

}