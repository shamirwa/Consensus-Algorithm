#include <stdint.h>

struct sig{
    uint32_t id; // the identifier of the signer
    uint8_t signature[256]; // since the length of private key is 2048 bits.
};

typedef struct SignedMessage{
    uint32_t type; // Must be equal to 1
    uint32_t total_sigs; // total number of signatures on the message
                         //   also indicates the round number

    uint32_t order; // the order (retreat = 0 and attack = 1)
    struct sig sigs[];  // contains total_sigs signatures
}SignedMessage;


typedef struct{
    uint32_t type;  // Must be equal to 2
    uint32_t round; // round number
}Ack;
