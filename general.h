#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <string>
#include <string.h>
#include <netdb.h>
#include <map>
#include <vector>
#include <set>
#include <unistd.h>
#include <math.h>
#include "message.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <sys/time.h>


using namespace std;

#define PORT 5000
#define debug 0
#define ACK_TIMER 100
#define ROUND_TIME 500
#define SIGN_TYPE 1
#define ACK_TYPE 2
#define SIG_STRUCT_SIZE 260
#define SIG_SIZE 256
#define XINU 0
#define VM 1

// Structure to keep the common information between sender and receiver side.
typedef struct{
    vector<string> hostNames;
    vector<string> hostIPAddr;
    map<string, string> hostNameToIP;
    map<string, uint32_t> ipToID;
    int roundNumber;

    // config parameters
    string hostFileName;
    int numFaulty;
    bool turnOnCrypto;
    int totalNumProcess;
    int commanderOrder;

    // Timer related informations
    struct timeval roundTimeStart;
    struct timeval roundTimerEnd;

    struct timeval ackTimerStart;
    struct timeval ackTimerEnd;

    double diffAckTime;
    double diffRoundTime;

    // ID to Private Key and certificate Map
    map<uint32_t, EVP_PKEY*> idToKey;
    map<uint32_t, EVP_PKEY*> idToCert;

    // Self information
    string selfHostName;
    uint32_t selfID;
}generalSystemInfo;


// Sender Information Struct
typedef struct{
    set<int> expectAckFrom;
    set<int>::iterator ackIter;
    int mySocket;
    map< int, SignedMessage* > procToMsgToSendList;
    map< int, SignedMessage* >::iterator it;

}senderInfo;

// Receiver Information struct
typedef struct{
    long int portNum;
    int mySocket;
    set<int> ordersReceived;
    map< int, SignedMessage* > procToMsgRcvdList;
    map< int, SignedMessage* >::iterator it;

}receiverInfo;


// Function to use all the error message
void error(const char msg[]);

// Function to print the help menu
void printUsage();

// Function to validate the port number passed
bool verifyPortNumber(long portNumber);

// Function to validate the hostfile passed
bool verifyHostFileName(string fileName);

// Function to validate the number of faulty process
bool verifyFaulty(int faultCount, string fileName, int* procCount);

// Return the index of the process from which ack is received
double getTimeDiff(struct timeval *start, struct timeval* end, bool print=false);

// Verify the ack message
bool verifyAckMessage(void* myMessage, generalSystemInfo systemInfo);

// Verify the Signed message
void verifyAndStoreSignedMessage(int readBufferLen, void* myMessage, 
        generalSystemInfo &systemInfo, senderInfo &mySenderSide, 
        receiverInfo &myReceiverSide);

// Function to send the ACK message to the sender
void sendAckMessage(string receiverIP, generalSystemInfo systemInfo, int portNum, 
                    senderInfo &mySenderSide);

// Function to make the decision
int choice(receiverInfo myReceiver);

string resolveHostNameToIP(string resolveName, map<string, string> passedMap);

uint32_t resolveIPToID(string resolveIP, map<string, uint32_t> passedMap);

void printMessage(SignedMessage* msg);

void convertByteOrder(SignedMessage* sigMessage, bool hton);

void convertAckByteOrder(Ack* ackMessage, bool hton);
