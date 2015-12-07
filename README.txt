**************************************************************
*******                                                 *****
*******      SORABH HAMIRWASIA                          *****
*******                                                 *****
**************************************************************

Files:
=====
1) general.cpp
2) general.h
3) message.h
4) pkiTool.sh
5) Makefile
6) openssl.cnf
7) hostfile.txt
8) CS505Project1Report.pdf  -- Report for the project.

Steps to generate the executable of the program and run it:-
====================================================
1) Go to the directory containing all the above mentioned files and run the
command "make". It will create an executable "general".

2) Create a hostfile with commander as the first entry in the hostfile.
I am submitting my hostfile.txt with this project.

3) Generate the private and public key pairs for all the hosts using the tool
"pkiTool.sh". The configuration file provided should be there in the same
directory. The certificates should be generated in the mc18 machine and then
needs to be copied on the VMS along with the PKI directory. 

    Execute the tool using the command:
    ===================================
    ./pkiTool.sh <hostfileName>

    Note: All keys will be generated inside a directory named PKI.

4) Execute the executable generated in step 1 using the command below:

    For commander:
    ==============
   ./general -p <portNumber> -h <hostFileName> -f <numberOfFaultyProc> -o
   <attack/retreat> [-c]

   For Lieutenant:
   ===============
   ./general -p <portNumber> -h <hostFileName> -f <numberOfFaultyProc> [-c]

5) To clean the executable. Run the command:

    make clean;
