#pragma once
#define BBBUFSIZE 64*1024
#define MAX_OPCODES 30

#define TAGCACHESIZE 1024*1024

#define MUTEXWAITPERIOD 6000

//mazimum number of args to store per external
#define MAX_ARG_STORAGE 20

#define OPUNDEF 0
#define OPJMP 1
#define OPRET 2
#define OPCALL 3

#define NONFLOW 0
#define JUMP 1
#define CALL 2
#define RETURN 3
#define EXTERNAL 4
#define NOSYM 8
#define AFTERRETURN 9
#define FIRST_IN_THREAD 10

#define INTERNAL_CODE 1 
#define EXTERNAL_CODE 2

#define MOD_INACTIVE 0  //don't plot this
#define MOD_ACTIVE 1	//plot this
#define MOD_UNINSTRUMENTED 2 //client didn't instrument further - usually windows dlls

//can leave a conditional 2 ways, keep record of what has happened
#define CONDPENDING 1
#define CONDFELLTHROUGH 2
#define CONDTAKEN 4
#define CONDCOMPLETE 8

#define BMULT 2

#define JUMPA -6
#define JUMPB 6
#define JUMPA_CLASH -15
#define CALLB 20
#define CALLA_CLASH -40
#define CALLB_CLASH -30
#define EXTERNA -3
#define EXTERNB 3
#define RETURNA_OFFSET -4
#define RETURNB_OFFSET 1

#define ARG_INT '0'
#define ARG_LONG '1'
#define ARG_B64 '2'