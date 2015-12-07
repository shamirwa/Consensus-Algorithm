#include "general.h"
#define TEST 0

void error(const char msg[])
{
    if(debug){
        fprintf(stderr,"Error: %s",msg);
    }
}

void printUsage(){
    printf("Usage: general -p port -h hostfile -f faulty [-c] [-o order]\n");
    exit(1);
}

// Function to validate the port number passed
bool verifyPortNumber(long portNumber){
    if (debug)
        fprintf(stderr, "Entered function verifyPortNumber\n");

    if(portNumber < 1024 || portNumber >65535){
        return false;
    }
    return true;
}

// Function to validate the hostfile passed
bool verifyHostFileName(string fileName){
    if(debug)
        fprintf(stderr, "Entered function verifyHostFileName\n");

    FILE *fp;
    fp = fopen(fileName.c_str(), "rb");
    if(!fp){
        return false;
    }
    fclose(fp);
    return true;
}

// Function to validate the number of faulty process
bool verifyFaulty(int faultCount, string fileName, int* procCount){
    if(debug)
        fprintf(stderr, "Enetered function verifyFaulty\n");

    FILE *fp = fopen(fileName.c_str(), "r");
    int numLine = 0;
    char ch;

    do{
        ch = fgetc(fp);
        if(ch == '\n'){
            numLine++;
        }
    }while(ch != EOF);

    fclose(fp);

    if(numLine < (faultCount + 2)){
        return false;
    }

    *procCount = numLine;
    return true;
}

// Function to calculate the time difference between start and end time
double getTimeDiff(struct timeval *start, struct timeval* end, bool print){

    if (print){
        fprintf(stderr, "Enetered function getTimeDiff\n");
    }
    double diffCalc = (end->tv_sec - start->tv_sec)*pow(10,3) + 
                                (end->tv_usec - start->tv_usec) / pow(10,3);
    return diffCalc;
}

// Verify the ack message
bool verifyAckMessage(void* myMessage, generalSystemInfo systemInfo)
{
    if(debug){
        fprintf(stderr, "Entered function verifyAckMessage\n");
    }
    bool isValid = false;

    Ack* ackMessage = (Ack*)myMessage;

    // Convert from network to host order
    convertAckByteOrder(ackMessage, false);

    if(ackMessage->type != ACK_TYPE){
        error("Invalid Ack message received, type is not 2\n");
        return isValid;
    }
    else if(ackMessage->round != systemInfo.roundNumber){
        error("Invalid Ack Message received, this message is \
                            from different round\n");
        return isValid;
    }

    isValid = true;
    return isValid;
}

// verify the signed message
void verifyAndStoreSignedMessage(int readBufferLen, void* myMessage, 
        generalSystemInfo &systemInfo, senderInfo &mySenderSide, 
        receiverInfo &myReceiverSide)
{
    if(debug){
        fprintf(stderr, "Enetered function verifyAndStoreSignedMessage\n");
    }

    bool isSignValid = true; // by default keeping it as true
    SignedMessage* sMessage = (SignedMessage*) myMessage;

    // Convert the message from network to host order'
    // CHANGE SORABH
    sMessage->total_sigs = ntohl(sMessage->total_sigs);

    int expMsgSize = sizeof(SignedMessage) + 
                            (sizeof(struct sig) * (sMessage->total_sigs));


    if(expMsgSize != readBufferLen){
        if(debug){
        fprintf(stderr, "The message size is not equal to the expected size.\n");
        fprintf(stderr, "Expected message size is %d and received is %d\n"
                ,expMsgSize, readBufferLen);
        }
        return;
    }
    
    convertByteOrder(sMessage, false);

    // Check for the message type
    if(sMessage->type != SIGN_TYPE){
        error("Invalid Signed Message received, type is not 1\n");
        return;
    }
    else if(sMessage->order < 0 || sMessage->order > 1){
        error("Invalid Signed Message received, order is not 0 or 1\n");
        return;
    }
    else if(sMessage->total_sigs < (systemInfo.roundNumber + 1) && 
                    (systemInfo.roundNumber != 0)){
        error("Invalid Signed Message received, this message is from past round\n");
        if(debug){
            fprintf(stderr, "System Round Number is %d and message is from %d\n", 
                                systemInfo.roundNumber, sMessage->total_sigs);
        }
        return;
    }

    // Check for the id's in the sig struct
    for(int i = 0; i<sMessage->total_sigs; i++){
        int currID = sMessage->sigs[i].id;

        if((currID < 1) || (currID > systemInfo.totalNumProcess)){
            
            if(debug){
                fprintf(stderr, "Invalid id found in sig struct inside msg\n");
            }
            return;
        }

    }

    // Check here for round number = 0
    if(sMessage->total_sigs > (systemInfo.roundNumber + 1) && 
            (systemInfo.roundNumber == 0)){
        if(debug){
            fprintf(stderr, "Message from future round received in round 0 by \
                                lieutenant %d", systemInfo.selfID);
        
            fprintf(stderr, "We will accept this message as this is the first \
                                message and proceed ahead\n"); 
        }

        // Update the round number to that of future message received
        systemInfo.roundNumber = sMessage->total_sigs -1;
        gettimeofday(&systemInfo.roundTimeStart, NULL);
    }

    // To print the data in message
    //printMessage(sMessage);

    if(systemInfo.turnOnCrypto){// check the signature if -c is not specified.

        if(debug){
            fprintf(stderr, "Verifying all the signatures\n");
        }
        // Total number of signatures are
        int sigNum = sMessage->total_sigs;
        int err;
        EVP_MD_CTX md_ctx;

        if(debug){
            fprintf(stderr, "Sig found in crypto: %d\n",sigNum); 
        }

        for(int i=sigNum - 1; i>=0; i--){

            // Verify the signature
            EVP_VerifyInit(&md_ctx, EVP_sha1());

            if(i > 0){
                EVP_VerifyUpdate(&md_ctx, sMessage->sigs[i-1].signature, SIG_SIZE);
            }else if(i == 0){
                EVP_VerifyUpdate(&md_ctx, &(sMessage->order), sizeof(uint32_t));
            }

            // Check if the id is valid or not
            if(sMessage->sigs[i].id < 1 || 
                    (sMessage->sigs[i].id > systemInfo.totalNumProcess)){
                if(debug){
                    fprintf(stderr, "Invalid IDi %d found in the sig struct of the \
                                        signed message\n", sMessage->sigs[i].id);
                    fprintf(stderr, "Considering the message as Invalid and discarding\n");
                }
                isSignValid = false;
                break;
            }

            err = EVP_VerifyFinal(&md_ctx, sMessage->sigs[i].signature, SIG_SIZE, \
                                        systemInfo.idToCert[sMessage->sigs[i].id]);

            if(err != 1){
                ERR_print_errors_fp(stderr);
                isSignValid = false;
                break;
            }
        }

    }

    if(systemInfo.roundNumber > 0){


        // For all rounds other than first, if the all signature is valid
        // and the order received is not in the set, then update the set with
        // the new order. If the received message is signed by less then f processes
        // then only store it to send in the next round. Else discard.
        if(isSignValid && (myReceiverSide.ordersReceived.find(sMessage->order) == 
                    myReceiverSide.ordersReceived.end()))
        {
            if(debug){
                fprintf(stderr, "All the signatures were verified ok\n");
            }

            //Store the order in the set
            myReceiverSide.ordersReceived.insert(sMessage->order);

            if(debug){
                fprintf(stderr, "Order storedin receiver list %d\n", sMessage->order);
            }

            // If num of sigs is less than total processes
            if(sMessage->total_sigs <= systemInfo.numFaulty)
            {
                if(debug){
                    fprintf(stderr, "Received the valid signed message in \
                                round %d\n", systemInfo.roundNumber);
                }
                // First store this message inside the map for all the process 
                // and then delete those for which id is found.
                for(int i=1; i <= systemInfo.totalNumProcess; i++){
                    myReceiverSide.procToMsgRcvdList[i] = sMessage;       
                }
                // Erase the process id for which signature is there in the message
                for(int i=0; i < sMessage->total_sigs; i++){
                    myReceiverSide.procToMsgRcvdList.erase(sMessage->sigs[i].id);
                }

                // Remove self process id too
                myReceiverSide.procToMsgRcvdList.erase(systemInfo.selfID);
            }
        }
    }
    else if(systemInfo.roundNumber == 0){

        if(isSignValid && myReceiverSide.ordersReceived.empty()){

            if(debug){
                fprintf(stderr, "Received the valid signed message in round 0\n");
            }
            // store the order
            myReceiverSide.ordersReceived.insert(sMessage->order);

            if(debug){
                fprintf(stderr, "Order Received by %d in round 0 is %d\n", 
                                systemInfo.selfID, sMessage->order);
            }

            // Since its the first round store the message for all the process 
            // except the commander and self
            for(int i=2; i <= systemInfo.totalNumProcess; i++)
            {
                if(i != systemInfo.selfID){
                    myReceiverSide.procToMsgRcvdList[i] = sMessage;
                }
            }
        }
    }
    else{
        // Free the message buffer as we are not storing this message
        if(sMessage){
            free(sMessage);
            sMessage = NULL;
        }
    }
}

// Function to send the acknowledgement
void sendAckMessage(string receiverIP, generalSystemInfo systemInfo, int portNum, 
                        senderInfo &mySenderSide){
    if(debug){
        fprintf(stderr, "Entered the function sendAckMessage\n");
    }

    // Create ACK message
    Ack* ackMessage = (Ack*) malloc(sizeof(Ack));

    if(!ackMessage){
        printf("Unable to allocate memory in sendAckMessage\n");
        return;
    }

    ackMessage->type = ACK_TYPE;
    ackMessage->round = systemInfo.roundNumber;

    struct sockaddr_in receiverAddr;

    if(mySenderSide.mySocket == -1){
        // Need to open a socket
        if((mySenderSide.mySocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
            error("Error while opening socket to send the ack message\n");
            exit(1);
        }
    }

    memset((char*)&receiverAddr, 0, sizeof(receiverAddr));
    receiverAddr.sin_family = AF_INET;
    receiverAddr.sin_port = htons(portNum);

    if(inet_aton(receiverIP.c_str(), &receiverAddr.sin_addr) == 0){
        error("INET_ATON Failed\n");
    }

    // Converting the ACK to network order before sending
    convertAckByteOrder(ackMessage, true);

    if(sendto(mySenderSide.mySocket, ackMessage, sizeof(Ack), 0, 
                (struct sockaddr*) &receiverAddr, sizeof(receiverAddr)) == -1){
        if(debug){
            fprintf(stderr, "Failed to send the ACK message in round %d to %s", 
                            systemInfo.roundNumber, receiverIP.c_str());
        }
    }
    else{
        if(debug){
            fprintf(stderr, "ACK successfully sent in round %d to %s by %s\n", 
            systemInfo.roundNumber, receiverIP.c_str(), systemInfo.selfHostName.c_str());
        }
    }

}

// Store the received signed message without verifying them as -c option is specified
void storeSignedMessage(void* myMessage, long mSize, generalSystemInfo systemInfo,
        int* storeOrder, senderInfo &mySenderSide){

    if(debug){
        fprintf(stderr, "Entered the function storeSignedMessage\n");
    }
    long signedSize = sizeof(SignedMessage);

    if(mSize < signedSize){
        error("Inavlid signed message received, size of the message is smaller\n");
        return;
    }

    SignedMessage* sMessage = (SignedMessage*) myMessage;
    // Check for the message type

    if(sMessage->type != SIGN_TYPE){
        error("Invalid Signed Message received, type is not 1\n");
        return;
    }
    else if(sMessage->order < 0 || sMessage->order > 1){
        error("Invalid Signed Message received, order is not 0 or 1\n");
        return;
    }
    else if(sMessage->total_sigs != (systemInfo.roundNumber + 1)){
        error("Invalid Signed Message received, this message is from \
                        different round\n");
        return;
    }
}

// Function to make a choice based on the final values
int choice(receiverInfo myReceiver){

    if(debug){
        fprintf(stderr, "Entered function choice\n");
    }

    if(myReceiver.ordersReceived.size() == 1){
        return *(myReceiver.ordersReceived.begin());
    }
    else{
        return 0;
    }
}

// Resolve Map Issues. Hostname to IP not used currently
string resolveHostNameToIP(string resolveName, map<string, string> passedMap){

    bool found = false;
    map<string, string>::iterator nameToIp;


    for(nameToIp = passedMap.begin(); nameToIp != passedMap.end(); nameToIp++){
        fprintf(stderr, "Resolve Host Name IP: %s, %s\n", 
                            nameToIp->first.c_str(), resolveName.c_str());
        if(nameToIp->first.compare(resolveName) == 0){
            found = true;
            return nameToIp->second;
        }
    }
    if(!found){
        fprintf(stderr, "Unable to resolve the hostname to IP from map\n");
    }
    return string("");
}

// Function to resolve the IP TO ID. Not used currently
uint32_t resolveIPToID(string resolveIP, map<string, uint32_t> passedMap){
    map<string, uint32_t>::iterator IPToID;
    bool found = false;


    for(IPToID = passedMap.begin(); IPToID != passedMap.end(); IPToID++){
        if(IPToID->first.compare(resolveIP) == 0){
            found = true;
            return IPToID->second;
        }
    }

    if(!found){
        fprintf(stderr, "Unable to resolve the IP to ID\n");
    }

    return 0;
}

// Function to print the data inside a message
void printMessage(SignedMessage* msg){

    if(debug){
        fprintf(stderr, "Type: %d\n", msg->type);
        fprintf(stderr, "Total Sigs: %d\n", msg->total_sigs);
        fprintf(stderr, "Order: %d\n", msg->order);
        fprintf(stderr, "ID: %d\n", msg->sigs[0].id);
    }
}

// To convert the byte order of the message
void convertByteOrder(SignedMessage* sigMessage, bool hton){

    if(hton){
        if(debug){
            fprintf(stderr, "Converting from host to network order\n");
        }
        sigMessage->type = htonl(sigMessage->type);
        sigMessage->order = htonl(sigMessage->order);

        for(int i=0; i<(sigMessage->total_sigs); i++){
            sigMessage->sigs[i].id = htonl((sigMessage->sigs[i]).id);
        }
        sigMessage->total_sigs = htonl(sigMessage->total_sigs);
    }
    else{
        if(debug){
            fprintf(stderr, "Converting from network order to host\n");
        }
        sigMessage->type = ntohl(sigMessage->type);
        sigMessage->order = ntohl(sigMessage->order);

        // CHANGE SORABH
	for(int i=0; i<sigMessage->total_sigs; i++){
            sigMessage->sigs[i].id = ntohl(sigMessage->sigs[i].id);
        }

    }
}

// To convert byte order of ACK message
void convertAckByteOrder(Ack* ackMessage, bool hton){

    if(hton){
        if(debug){
            fprintf(stderr, "Converting Ack from host to network order\n");
        }
        ackMessage->type = htonl(ackMessage->type);
        ackMessage->round = htonl(ackMessage->round);
    }
    else{
        if(debug){
            fprintf(stderr, "Converting Ack from network to host order\n");
        }
        ackMessage->type = ntohl(ackMessage->type);
        ackMessage->round = ntohl(ackMessage->round);
    }
}

// **** MAIN FUNCTION **** //
int main(int argc, char* argv[])
{
    int argCount = 1;
    bool isCommanderProc = false;

    generalSystemInfo mySystemInfo;
    mySystemInfo.turnOnCrypto = true;
    mySystemInfo.totalNumProcess = 0;
    mySystemInfo.commanderOrder = 0;
    mySystemInfo.roundNumber = 0;

    // Sender Information structure
    senderInfo sender;

    // Receiver Information structure
    receiverInfo receiver;

    // Variables for SECURITY
    int err;
    unsigned int sig_len = SIG_SIZE;
    unsigned char sig_buf [SIG_SIZE];
    EVP_MD_CTX md_ctx;
    EVP_PKEY* pkey;
    FILE* fpSecurity;
    X509* x509;

    // Load the crypto library error strings */
    ERR_load_crypto_strings();

    // Implement the command line option parser
    if(argc < 7)
    {
        // Insufficient number of options entered
        error("Invalid command entered\n");
        printUsage();
    }

    do{
        // Get the port number
        if(strcmp(argv[argCount], "-p") == 0){
            long port = atoi(argv[++argCount]);
            if(verifyPortNumber(port)){
                receiver.portNum =  port;
            }
            else{
                error("Invalid Port Number entered\n");
                exit(1);
            }
            argCount++;
        }
        // Get the host file name
        if(strcmp(argv[argCount], "-h") == 0){
            string fileName(argv[++argCount]);
            if(verifyHostFileName(fileName)){
                mySystemInfo.hostFileName = fileName;
            }
            else{
                error("Invalid hostfile name entered\n");
                exit(1);
            }
            argCount++;
        }

        // Get the faulty process count
        if(strcmp(argv[argCount], "-f") == 0){
            int faultyCount = atoi(argv[++argCount]);

            if(verifyFaulty(faultyCount, mySystemInfo.hostFileName, 
                        &mySystemInfo.totalNumProcess)){
                mySystemInfo.numFaulty = faultyCount;
            }
            else{
                error("Invalid faulty process count enetered \n");
                exit(1);
            }
            argCount++;
        }

        // Get the optional arguments
        if(argc > 7){
            if (debug)
                fprintf(stderr, "Optional Args present\n");

            if(strcmp(argv[argCount], "-c") == 0){
                argCount++;
                mySystemInfo.turnOnCrypto = false;
            }
            else if(strcmp(argv[argCount], "-o") == 0){
                isCommanderProc = true; 
                string order(argv[++argCount]);

                if(order.compare("attack") == 0){
                    // Taking 1 as attack and 0 as retreat
                    mySystemInfo.commanderOrder = 1;
                }
                else if(order.compare("retreat") == 0){
                    mySystemInfo.commanderOrder = 0;
                }
                else{
                    error("Invalid order entered \n");
                    exit(1);
                }

                argCount++;
            }

        }

    }while(argCount < argc); 

    if(debug){
        fprintf(stderr, "Inside the print if\n");
        fprintf(stderr, "Enetered port number is: %ld\n", receiver.portNum);
        fprintf(stderr, "Entered host file name is: %s\n", 
                                    mySystemInfo.hostFileName.c_str());
        fprintf(stderr, "Number of faulty process is: %d\n", mySystemInfo.numFaulty);

        if(mySystemInfo.turnOnCrypto)
            fprintf(stderr, "Crypto is on\n");
        else
            fprintf(stderr, "Crypto is off\n");

    }

    struct in_addr **ipAddr;
    struct hostent* he;
    FILE* fp = fopen(mySystemInfo.hostFileName.c_str(), "r");

    if(debug){
        fprintf(stderr, "total process: %d\n", mySystemInfo.totalNumProcess);
    }
    // Get self hostname
    char myName[100];
    gethostname(myName, 100);
    mySystemInfo.selfHostName = myName;

    struct sockaddr_in lieuAddr;
    struct sockaddr_in senderProcAddr;
    struct sockaddr_in myInfo;

    for(int i = 0; i<mySystemInfo.totalNumProcess; i++){

        if(fp == NULL){
            error("Unable to open the hostfile\n");
            exit(1);
        }

        // Get the ipaddress of all the hosts.
        char currHost[100];

        if(fgets(currHost, 100, fp) != NULL){
            mySystemInfo.hostNames.push_back(currHost);
            if(mySystemInfo.hostNames[i].rfind('\n') != string::npos){
                mySystemInfo.hostNames[i].erase(--(mySystemInfo.hostNames[i].end()));
            }

        }

        if((he = gethostbyname(mySystemInfo.hostNames[i].c_str())) == NULL){
            fprintf(stderr, "Unable to get the ip address of the host: %s\n",
                                                        currHost);
            exit(1);
        }

        //Store the ip address
        ipAddr = (struct in_addr**)he->h_addr_list;

        if(mySystemInfo.selfHostName.compare(mySystemInfo.hostNames[i]) == 0){
            string currentIP = inet_ntoa(*ipAddr[XINU]);

            if(currentIP.find("127") != string::npos){
                mySystemInfo.hostIPAddr.push_back(inet_ntoa(*ipAddr[VM]));
            }
            else{
                mySystemInfo.hostIPAddr.push_back(inet_ntoa(*ipAddr[XINU]));
            }
        }
        else{
            mySystemInfo.hostIPAddr.push_back(inet_ntoa(*ipAddr[XINU]));
        }

        // update the map
        mySystemInfo.ipToID.insert(pair<string, int>(mySystemInfo.hostIPAddr[i], i+1));
        mySystemInfo.hostNameToIP.insert(
                    pair<string, string>(mySystemInfo.hostNames[i], 
                                        mySystemInfo.hostIPAddr[i]));


        // Store the private key and certificates into the map
        string keyFileName = "./PKI/host_";
        keyFileName.append(mySystemInfo.hostNames[i]);
        keyFileName.append("_key.pem");

        FILE* keyFp = fopen(keyFileName.c_str(), "r");
        if(keyFp == NULL){
            fprintf(stderr, "Unable to open the private key file %s\n", 
                            keyFileName.c_str());
            exit(1);
        }
        pkey = PEM_read_PrivateKey(keyFp, NULL, NULL, NULL);
        fclose(keyFp);

        if(pkey == NULL){
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        mySystemInfo.idToKey.insert(pair<uint32_t, EVP_PKEY*>(i+1, pkey));


        // Storethe certificates into the map
        string certFileName = "./PKI/host_";
        certFileName.append(mySystemInfo.hostNames[i]);
        certFileName.append("_cert.pem");

        FILE* certFp = fopen(certFileName.c_str(), "r");
        if(certFp == NULL){
            fprintf(stderr, "Unable to open the certificate file %s\n", 
                                    certFileName.c_str());
            exit(1);
        }

        x509 = PEM_read_X509(certFp, NULL, NULL, NULL);
        fclose(certFp);

        if(x509 == NULL){
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        pkey = X509_get_pubkey(x509);

        if(pkey == NULL){
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        mySystemInfo.idToCert.insert(pair<uint32_t, EVP_PKEY*>(i+1, pkey));

        if (debug)
            fprintf(stderr, "Host name: %s, Ip address: %s\n",
                            mySystemInfo.hostNames[i].c_str(), 
                            mySystemInfo.hostIPAddr[i].c_str());

    }
    fclose(fp);

    mySystemInfo.selfID = 
        mySystemInfo.ipToID[mySystemInfo.hostNameToIP[mySystemInfo.selfHostName]];

    if(debug){
        fprintf(stderr, "Self hostname is %s\n", mySystemInfo.selfHostName.c_str());
        fprintf(stderr, "Self IP Address is %s\n", 
                mySystemInfo.hostNameToIP[mySystemInfo.selfHostName].c_str());
        fprintf(stderr, "Self ID is %d\n", mySystemInfo.selfID);
    }


    // To store the address of sender of ACK
    memset((char*)&senderProcAddr, 0, sizeof(senderProcAddr));
    socklen_t senderLen = sizeof(senderProcAddr);

    // store the info for sending the message
    memset((char*)&lieuAddr, 0, sizeof(lieuAddr));
    lieuAddr.sin_family = AF_INET;
    lieuAddr.sin_port = htons(receiver.portNum);

    // Store the info to bind receiving port with the socket.
    memset((char*)&myInfo, 0, sizeof(myInfo));
    myInfo.sin_family = AF_INET;
    myInfo.sin_port = htons(receiver.portNum);
    myInfo.sin_addr.s_addr = htonl(INADDR_ANY);

    // Open a sender socket to send the messages
    if((sender.mySocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
        error("Error when trying to open the socket to send message\n");
        exit(1);
    }

    // Open a receiver socket to receive the message
    if((receiver.mySocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
        error("Error when trying to open the receiving socket \n");
                            
        exit(1);
    }

    // bind the receiver socket
    if(bind(receiver.mySocket, (struct sockaddr*) &myInfo, sizeof(myInfo)) == -1){
        error("Bind failed for receiving socket \n");
        exit(1);
    }


    if(debug)
        fprintf(stderr, "Self Name: %s and self ID: %d\n",
                        mySystemInfo.selfHostName.c_str(), mySystemInfo.selfID);

    // If its a commander process then just send the message to all the 
    // lieutenant and quit. ID of commander process is 1

    int totalRound = mySystemInfo.numFaulty + 1;

    for(; mySystemInfo.roundNumber < totalRound; mySystemInfo.roundNumber++)
    {
        if(debug){
            fprintf(stderr, "Round Number is %d\n", mySystemInfo.roundNumber);
        }

        if(isCommanderProc && (mySystemInfo.roundNumber == 0)){

            // Sleep commander for few seconds so that other process are started
            sleep(1);

            for(int i = 1; i < mySystemInfo.totalNumProcess; i++){
                sender.expectAckFrom.insert(i+1);
            }

            // send the signed message to all the process from whom ack is not received
            int buffSize = sizeof(SignedMessage) + 
                            (sizeof(struct sig) * (mySystemInfo.roundNumber + 1));
            SignedMessage *myMessage = (SignedMessage*)malloc(buffSize);

            if(!myMessage){
                printf("Unable to malloc in round 0 for commander\n");
                printf("Exiting the application\n");
                exit(1);    
            }

            myMessage->type = SIGN_TYPE;
            myMessage->total_sigs = mySystemInfo.roundNumber + 1;
            myMessage->order = mySystemInfo.commanderOrder;

            // Fill the sigs array
            myMessage->sigs[0].id = mySystemInfo.selfID;

            if(debug){
                fprintf(stderr, "ID: while sending %d\n", myMessage->sigs[0].id);
            }

            // Sign the message
            EVP_SignInit(&md_ctx, EVP_sha1());
            EVP_SignUpdate(&md_ctx, &(myMessage->order), sizeof(uint32_t));

            err = EVP_SignFinal(&md_ctx, myMessage->sigs[0].signature, &sig_len, 
                                    mySystemInfo.idToKey[mySystemInfo.selfID]);

            if(err != 1){
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "Error while signing the message by commander\n");
                //exit(1);
            }

            // Allocate memory for receiving message
            void* message = (void*) malloc(sizeof(SignedMessage));

            if(!message){
                printf("Unable to malloc in round 0 for commander for receiving message\n");
                printf("Exiting the application\n");
                exit(1);
            }

            // convert the message to network order before sending
            // CHANGE SORABH
            convertByteOrder(myMessage, true);

            // start the round timer
            gettimeofday(&mySystemInfo.roundTimeStart, NULL);

            // send signed message to all the other processes
            do{
                // send the signed message to all the process from whom ack is not received
                for(sender.ackIter = sender.expectAckFrom.begin(); 
                                sender.ackIter != sender.expectAckFrom.end(); 
                        sender.ackIter++){

                    if(inet_aton(mySystemInfo.hostIPAddr[(*sender.ackIter - 1)].c_str(), 
                                                &lieuAddr.sin_addr) == 0){
                        error("INET_ATON failed\n");
                        //exit(1);
                    }

                    if(TEST){
                        // For Testing Purpose 
                        if(*sender.ackIter == 2){
                            myMessage->order = 0;
                            //EVP_SignInit(&md_ctx, EVP_sha1());
                            //EVP_SignUpdate(&md_ctx, &(myMessage->order), sizeof(uint32_t));

                            //err = EVP_SignFinal(&md_ctx, myMessage->sigs[0].signature, &sig_len,
                            //        mySystemInfo.idToKey[mySystemInfo.selfID]);

                        }
                        else{
                            myMessage->order = 1;
                        }
                    }


                    if(sendto(sender.mySocket, myMessage, buffSize, 0, 
                            (struct sockaddr*) &lieuAddr, sizeof(lieuAddr)) == -1){
                            if(debug){
                                fprintf(stderr, "Commander Failed to send the mesage \
                                        to %s\n", 
                            mySystemInfo.hostIPAddr[(*sender.ackIter - 1)].c_str());
                            }
                    }else{
                            if(debug){
                                fprintf(stderr, "Commander has sent the message \
                            to %s\n", mySystemInfo.hostIPAddr[(*sender.ackIter - 1)].c_str());
                            }
                        }
                }

                // Commander has send the messaged to all the other lieu. No we need to 
                // start the ack time.
                gettimeofday(&mySystemInfo.ackTimerStart, NULL);


                int status = -1;
                int ackIndex = -1;

                do{
                    status = recvfrom(receiver.mySocket, message, sizeof(SignedMessage), 
                        MSG_DONTWAIT, (struct sockaddr*) &senderProcAddr, &senderLen);

                    if(status > 0){

                        ackIndex = -1;
                        string currIp = inet_ntoa(senderProcAddr.sin_addr);
                        ackIndex = mySystemInfo.ipToID[currIp];

                        // Validate the ack message. If its not ack or ack with 
                        // wrong parameters then exit the system.
                        bool isAckValid = verifyAckMessage(message, mySystemInfo);

                        // Remove the id from the set from which ack has been received
                        if(isAckValid){
                            if(debug){
                                fprintf(stderr, "Valid ack received by commander \
                                            from process %d\n", ackIndex);
                            }

                            sender.ackIter = sender.expectAckFrom.find(ackIndex);

                            if(sender.ackIter != sender.expectAckFrom.end()){
                                sender.expectAckFrom.erase(sender.ackIter);
                            }else{
                                // A meesage with unexpected process is received
                                if(debug){
                                    fprintf(stderr, "UNKNOW ACK received from %d\n", 
                                                    (ackIndex));
                                }
                            }
                        }else{
                            if(debug){
                                fprintf(stderr, "Invalid ack received by commander \
                                                from process %d\n", ackIndex);
                            }
                        }
                    }
                    else if(status < 0){
                        if((errno != EWOULDBLOCK) && (errno != EAGAIN)){
                            if(debug){
                                fprintf(stderr, "Error while receiving ack by commander\n");
                            }
                        }
                    }

                    gettimeofday(&mySystemInfo.ackTimerEnd, NULL);
                    mySystemInfo.diffAckTime = getTimeDiff(
                                        &mySystemInfo.ackTimerStart, 
                                        &mySystemInfo.ackTimerEnd);

                    // Reset the ACK message
                    memset(message, 0, sizeof(SignedMessage));
                }while(mySystemInfo.diffAckTime < ACK_TIMER); // Receive the ack 
                                             //message till your ack timer expires.

                gettimeofday(&mySystemInfo.roundTimerEnd, NULL);
                mySystemInfo.diffRoundTime = getTimeDiff(
                                        &mySystemInfo.roundTimeStart, 
                                        &mySystemInfo.roundTimerEnd);

            }while(mySystemInfo.diffRoundTime < ROUND_TIME); // Send till you 
                                               // round timer doesnot expires.

        }
        else if(!isCommanderProc){   // Process is a general lieutenant not a commander

            // Process will try to receive the message. If the received message 
            // is an ack one then he will mark his ack array to true.
            // 2) If the received message is a signed message then verify it
            // the signature and send the ack to the sender and send the signed 
            // message to all the other process who has not signed this message

            // We need to handle the first round in different way from other rounds.
            if(mySystemInfo.roundNumber == 0){

                if(debug){
                    fprintf(stderr, "In round zero for lieutenants\n");
                }

                // Here we can get the message from any round as it might be the 
                // case that this lieutenant arrives late into the system
                int buffSize = (sizeof(SignedMessage) + 
                            (sizeof(struct sig) * (mySystemInfo.numFaulty + 1)));
                void* message = (void*) malloc(buffSize);

                if(!message){
                    printf("Unable to allocate memory for lieutenant in round 0");
                    printf(" for receiving messages\n");
                    printf("Exiting the application\n");
                    exit(1);
                }

                bool firstMsgRcvd = false;

                // Start the round timer
                gettimeofday(&mySystemInfo.roundTimeStart, NULL);

                // Receive till the first round time expires
                int status = -1;
                do{
                    // If commander drops all the message and none of the lieutenant receives any message
                    // Than we will remain block here. Need to handle this case.
                    if(!firstMsgRcvd){
                        if(debug){
                            fprintf(stderr, "Receiving First Message\n");
                        }
                        status = recvfrom(receiver.mySocket, message, buffSize, 0, 
                                (struct sockaddr*) &senderProcAddr, &senderLen);
                        firstMsgRcvd = true;
                    }
                    else{
                        status = recvfrom(receiver.mySocket, message, buffSize, 
                         MSG_DONTWAIT, (struct sockaddr*) &senderProcAddr, &senderLen);
                    }

                    if(status > 0){
                        string currIp = inet_ntoa(senderProcAddr.sin_addr);

                        if(debug){
                            fprintf(stderr, "Signed message received by process \
                                %d from process %s of size %d\n", mySystemInfo.selfID, 
                                currIp.c_str(), status); 
                        }

                        // Validate the signed message. 
                        verifyAndStoreSignedMessage(status, message, 
                                            mySystemInfo, sender, receiver);

                        // Send the ACK
                        sendAckMessage(currIp, mySystemInfo, receiver.portNum, sender);
                    }
                    else if(status < 0){
                        if((errno != EWOULDBLOCK) && (errno != EAGAIN)){
                            if(debug){
                                fprintf(stderr, "Error in process %d while receiving message\n",
                                        mySystemInfo.selfID);
                            }
                        }

                    }

                    gettimeofday(&mySystemInfo.roundTimerEnd, NULL);
                    mySystemInfo.diffRoundTime = getTimeDiff(
                                            &mySystemInfo.roundTimeStart, 
                                            &mySystemInfo.roundTimerEnd);

                }while(mySystemInfo.diffRoundTime < ROUND_TIME);

            }// End of round zero
            else{
                // For all the other rounds
                if(debug){
                    fprintf(stderr, "For rounds greater than zero in lieutenant process\n");
                }

                // Store the process id from which Ack is expected
                for(sender.it = sender.procToMsgToSendList.begin(); 
                        sender.it != sender.procToMsgToSendList.end(); sender.it++){

                    sender.expectAckFrom.insert(sender.it->first);
                }

                // start the round timer
                gettimeofday(&mySystemInfo.roundTimeStart, NULL);

                // send messages to all the process from the map
                do{
                    // Send the Signed Message received in last round to 
                    // valid processes.
                    SignedMessage *storedMessage = NULL;

                    for(sender.ackIter = sender.expectAckFrom.begin();
                            sender.ackIter != sender.expectAckFrom.end(); 
                            sender.ackIter++){

                        if(inet_aton(mySystemInfo.hostIPAddr[(*sender.ackIter - 1)].c_str(), 
                                            &lieuAddr.sin_addr) == 0){
                            error("INET_ATON failed for general round\n");
                        }

                        // Need to create the message with  new signature and the stored message.
                        storedMessage = sender.procToMsgToSendList[*sender.ackIter];

                        // Allocate the memory for new message and copy all 
                        // the signatures, values from stored one. Dont change the stored message 
                        // as we may need to re-send it if ACK is not received
                        long buffSize = sizeof(SignedMessage) + 
                                    (sizeof(struct sig) * (storedMessage->total_sigs + 1));
                        SignedMessage *sigMessage = (SignedMessage*)malloc(buffSize);

                        if(!sigMessage){
                            printf("Unable to allocate memory for signed message");
                            printf(" in lieutenant while sending the message in ");
                            printf("general round \n Exiting the application\n");
                            exit(1);
                        }

                        sigMessage->total_sigs = storedMessage->total_sigs + 1;
                        sigMessage->type = SIGN_TYPE;

                        // Testing
                        if(TEST){
                            if(mySystemInfo.selfID == 2){
                                sigMessage->order = 0;
                            }else{
                                sigMessage->order = storedMessage->order;
                            }
                        }
                        else{
                            sigMessage->order = storedMessage->order;
                        }

                        memcpy(sigMessage->sigs, storedMessage->sigs,
                                    (sizeof(struct sig) * (storedMessage->total_sigs)));
                        sigMessage->sigs[sigMessage->total_sigs - 1].id =  
                                                    mySystemInfo.selfID; // SELF ID

                        // Need to sign by the current process and store it in 
                        // the new message
                        EVP_SignInit(&md_ctx, EVP_sha1());
                        EVP_SignUpdate(&md_ctx, 
                                sigMessage->sigs[sigMessage->total_sigs - 2].signature, 
                                SIG_SIZE);

                        err = EVP_SignFinal(&md_ctx, 
                                sigMessage->sigs[sigMessage->total_sigs - 1].signature, 
                                &sig_len, mySystemInfo.idToKey[mySystemInfo.selfID]);

                        if(err != 1){
                            ERR_print_errors_fp(stderr);
                            fprintf(stderr, "Failed to sign the message\n");
                        }


                        // Convert the byte order
                        convertByteOrder(sigMessage, true);

                        if(sendto(sender.mySocket, sigMessage, buffSize, 0, (
                                    struct sockaddr*)&lieuAddr, sizeof(lieuAddr)) == -1){
                            if(debug){
                                fprintf(stderr, "Error in sending the signed message \
                                            in round %d\n", mySystemInfo.roundNumber);
                            }
                        }
                        else{
                            
                            if(debug){
                                fprintf(stderr, "Signed message sent to process: %s by\
                                            process: %d in round: %d\n", 
                                    mySystemInfo.hostIPAddr[(*sender.ackIter - 1)].c_str(),
                                    mySystemInfo.selfID, mySystemInfo.roundNumber);
                            }
                        }
                        // After sending the message free the buffer
                        if(sigMessage){
                            free(sigMessage);
                            sigMessage = NULL;
                        }
                    }

                    // Process has sent the message to all the other valid 
                    // process. Now start the ack timer
                    gettimeofday(&mySystemInfo.ackTimerStart, NULL);

                    // Receive the message sent by the sender
                    int status = -1;
                    int ackIndex = -1;
                    do{
                        int buffSize = sizeof(SignedMessage) + 
                             (sizeof(struct sig) * (mySystemInfo.roundNumber + 1));
                        void* recvdMsg = (void*) malloc(buffSize);

                        // Exit the application if the malloc failed
                        if(!recvdMsg){
                            printf("Unable to allocate the memory for lieutenants");
                            printf(" for receiving the message in general round\n");
                            printf("Exiting the application\n");
                            exit(1);
                        }


                        status = recvfrom(receiver.mySocket, recvdMsg, buffSize, 
                                MSG_DONTWAIT, (struct sockaddr*)&senderProcAddr, 
                                &senderLen);

                        if(status > 0){
                            ackIndex = -1;

                            // check the type of message
                            uint32_t *msgType = (uint32_t*) malloc(sizeof(uint32_t));

                            // Exit the application if malloc failed
                            if(!msgType){
                                printf("Unable to allocate the memory for msgType\n");
                                printf("Exiting the application\n");
                                exit(1);
                            }

                            memcpy(msgType, recvdMsg, sizeof(uint32_t));

                            uint32_t type = *msgType;
                            type = htonl(type);
                            string senderIP = inet_ntoa(senderProcAddr.sin_addr);

                            // If message is ACK type
                            if(type == ACK_TYPE){
                                ackIndex = mySystemInfo.ipToID[senderIP];

                                //Validate the ack message. If its not an ack 
                                //then discard the message
                                bool isAckValid = verifyAckMessage(recvdMsg, 
                                                                mySystemInfo);

                                // Remove the id from the sender expected ack list
                                if(isAckValid){
                                    sender.ackIter = sender.expectAckFrom.find(ackIndex);

                                    if(sender.ackIter != sender.expectAckFrom.end()){
                                        sender.expectAckFrom.erase(sender.ackIter);
                                        if(debug){
                                           fprintf(stderr, "Valid ACK received by \
                                           the lieutenant process %d from %s\n", 
                                           mySystemInfo.selfID, senderIP.c_str()); 
                                        }
                                    }
                                    else{
                                        if(debug){
                                            fprintf(stderr, "UNEXPECTED ACK received \
                                            from a process in general round %d\n", 
                                            mySystemInfo.roundNumber);
                                        }
                                    }
                                }
                                else{
                                    if(debug){
                                        fprintf(stderr, "Invalid ACK received, \
                                        discarding in general round %d\n", 
                                        mySystemInfo.roundNumber);
                                    }
                                }

                                // Deallocate the memory
                                if(recvdMsg){
                                    free(recvdMsg);
                                    recvdMsg = NULL;
                                }
                            }

                            // If message is signed type
                            if(type == SIGN_TYPE){
                                if(debug){
                                    fprintf(stderr, "Verifying signed message in \
                                    general round %d\n", mySystemInfo.roundNumber); 
                                }

                                // Validate the signed message. 
                                verifyAndStoreSignedMessage(status, recvdMsg, 
                                                mySystemInfo, sender, receiver);

                                // Send the ACK
                                sendAckMessage(senderIP, mySystemInfo,
                                        receiver.portNum, sender);

                            }
                        }
                        else if(status < 0){

                            if((errno != EWOULDBLOCK) && (errno != EAGAIN)){
                                if(debug){
                                    fprintf(stderr, "Error while receiving ack by commander\n");
                                }
                            }

                            if(recvdMsg){
                                free(recvdMsg);
                                recvdMsg = NULL;

                            }
                        }

                        gettimeofday(&mySystemInfo.ackTimerEnd, NULL);
                        mySystemInfo.diffAckTime = getTimeDiff(
                                        &mySystemInfo.ackTimerStart, 
                                        &mySystemInfo.ackTimerEnd);

                    }while(mySystemInfo.diffAckTime < ACK_TIMER); // Retry to recive 
                                                      // until the ack timer expires


                    gettimeofday(&mySystemInfo.roundTimerEnd, NULL);
                    mySystemInfo.diffRoundTime = getTimeDiff(
                                &mySystemInfo.roundTimeStart, 
                                &mySystemInfo.roundTimerEnd);

                }while(mySystemInfo.diffRoundTime < ROUND_TIME);

            }

            // Reset all the sender parameter
            sender.expectAckFrom.clear();
            sender.procToMsgToSendList.clear();


            // Copy the signed message from receiver list of this round to 
            // sender of next round Reset the receiver list
            sender.procToMsgToSendList = receiver.procToMsgRcvdList;

            // Here check that do we need to point all the SignedMessage 
            // pointer to null before clear. As that might delete the memory
            receiver.procToMsgRcvdList.clear();
        }
        if(debug){
            fprintf(stderr,"size of sender list %ld\n", 
                                sender.procToMsgToSendList.size());
        }
    } // End of For Loop

    if(isCommanderProc){
        if(mySystemInfo.commanderOrder == 1){
            printf("Commander Process with ID %d: agreed on attack\n",
                                        mySystemInfo.selfID);
        }
        else{
            printf("Commander Process with ID %d: agreed on retreat\n",
                                        mySystemInfo.selfID);
        }
    }
    else
    {
        int decide = 0;
        decide = choice(receiver);

        if(decide == 0){
            printf("Process with ID %d: agreed on retreat\n", 
                                        mySystemInfo.selfID);
        }
        else{
            printf("Process with ID %d: agreed on attack\n", 
                                        mySystemInfo.selfID);
        }
    }

    // Close the sockets
    close(receiver.mySocket);
    close(sender.mySocket);
}
