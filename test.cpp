#include <map>
#include <string>
#include <stdio.h>
#include <set>
using namespace std;


int main(){

    map<pair<int, int>, string> myMap;
    map<int, set<int> > myMap2;

    myMap[make_pair(1,2)] = "Sorabh";
    myMap[make_pair(1,1)] = "Ravi";
    myMap[make_pair(1,3)] = "Kushal";

    map<pair<int, int>, string>::iterator iter;

    myMap2[1].insert(1);

    for(iter = myMap.begin(); iter != myMap.end(); iter++){
        printf("Key: %d, %d and Value %s\n",iter->first.first, iter->first.second, iter->second.c_str());
    }

    if(myMap2[1].find(1) != myMap2[1].end()){
        printf("Hello\n");
    }
    else{
        printf("Not found\n");
    }

    printf("Size is %d", myMap2[1].size());

    printf("\nValue: %s",myMap[make_pair(1,2)].c_str());
    return 0;
}
