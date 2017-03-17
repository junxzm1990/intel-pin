/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <list>
#include <sstream>
#include <assert.h>
#include <stdio.h>
#include <iomanip>
#include "syscallent.h"

/* ================================================================== */
// Global variables 
/* ================================================================== */

UINT64 insCount = 0;        //number of dynamically executed instructions
UINT64 bblCount = 0;        //number of dynamically executed basic blocks
UINT64 threadCount = 0;     //total number of threads, including main thread

std::ostream * out = &cerr;
std::ostream * sysout = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for MyPinTool output");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");

KNOB<string> KnobXmmFile(KNOB_MODE_WRITEONCE,  "pintool",
    "xmm", "", "specify file name for logging xmm registers");

KNOB<string> KnobSysFile(KNOB_MODE_WRITEONCE,  "pintool",
    "sys", "", "specify file name for logging arguments for system call");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID CountBbl(UINT32 numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

string Val2Str(const void* value, unsigned int size)
{
    stringstream sstr;
    sstr << hex;
    const unsigned char* cval = (const unsigned char*)value;
    // Traverse cval from end to beginning since the MSB is in the last block of cval.

    while (size)
    {
        --size;
        sstr << setfill('0') <<setw(2) << (unsigned int)cval[size];
    }

    return string("0x")+sstr.str();
}


const char * dumpInstructions(INS ins){

	std::stringstream ss; 
	ss << INS_Disassemble(ins);
	return strdup(ss.str().c_str());

}

std::list<REG> * listRegisters(INS ins){

	std::list<REG> * registers = new std::list<REG>;

	for (UINT i = 0; i < INS_OperandCount(ins); i++){

		if(INS_OperandIsReg(ins, i)){
			REG reg = INS_OperandReg(ins, i);
			registers->push_back(reg);
		}
	}

	return registers; 
}

std::list<REG> * listMemRegisters(INS ins){

        std::list<REG> * registers = new std::list<REG>;

        for (UINT i = 0; i < INS_OperandCount(ins); i++){

                if(INS_OperandIsMemory(ins, i)){
                        registers->push_back(INS_OperandMemoryBaseReg(ins, i));
                        registers->push_back(INS_OperandMemoryIndexReg(ins, i));
                }
        }

        return registers;
}


UINT regWidth2Size(REG reg){

	switch(REG_Width(reg)){

		case REGWIDTH_8:
			return 1; 

		case REGWIDTH_16:
			return 2; 
	
		case REGWIDTH_32:
			return 4;

		case REGWIDTH_64:
			return 8;

		case REGWIDTH_80:
			return 10;

		case REGWIDTH_128:
			return 16;

		case REGWIDTH_256:
			return 32;

		case REGWIDTH_512:
			return 64;

		case REGWIDTH_FPSTATE:
			return 16;			
 
		default: 
			return 4;
	}
}


VOID LogInstDetail(THREADID threadID, ADDRINT address, const CONTEXT *ctx, const char* disasm, void * regdata, void *memdata){
	
	std::list<REG> * registers = (std::list<REG> *)regdata;
		
	std::list<REG> * memreg = (std::list<REG> *)memdata;

	*out << threadID << "-" << std::hex << address << "-" << disasm;

	for(std::list<REG>::iterator it = registers ->begin(); it != registers->end(); it++){
		*out << "-OR";

		REG reg = (*it);
		std::string name = REG_StringShort(reg);
		*out<< name.c_str() << ":";

		PIN_REGISTER regval; 
		
		PIN_GetContextRegval(ctx, reg, reinterpret_cast<UINT8*>(&regval));
		
		*out << std::hex << Val2Str(&regval, regWidth2Size(reg));
	}


	for(std::list<REG>::iterator it = memreg ->begin(); it != memreg->end(); it++){
		*out << "-OM";

		REG reg = (*it);
		std::string name = REG_StringShort(reg);
		*out<< name.c_str() << ":";

		PIN_REGISTER regval; 
		
		PIN_GetContextRegval(ctx, reg, reinterpret_cast<UINT8*>(&regval));
		
		*out << std::hex << Val2Str(&regval, regWidth2Size(reg));
	}

	*out << endl;
}


VOID Trace(INS ins,  VOID *v){

	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogInstDetail, IARG_THREAD_ID, IARG_INST_PTR, IARG_CONTEXT, IARG_PTR, dumpInstructions(ins), IARG_PTR, (void*)listRegisters(ins), IARG_PTR, (void*)listMemRegisters(ins), IARG_END);
}

/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           thread creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddThreadStartFunction function call
 */
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    threadCount++;
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    *out <<  "===============================================" << endl;
    *out <<  "MyPinTool analysis results: " << endl;
    *out <<  "Number of instructions: " << insCount  << endl;
    *out <<  "Number of basic blocks: " << bblCount  << endl;
    *out <<  "Number of threads: " << threadCount  << endl;
    *out <<  "===============================================" << endl;
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */


BOOL Intercept(THREADID, INT32 sig, CONTEXT *ctx, BOOL, const EXCEPTION_INFO *, VOID *){
    std::cerr << "Intercepted signal " << sig << std::endl;


    //std::ostream * xmmout = &cerr;


    string fileName = KnobXmmFile.Value();


    FILE * pFile;

    pFile = fopen (fileName.c_str(), "wb");

    PIN_REGISTER regval;


    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_XMM0, reinterpret_cast<UINT8*>(&regval));
   fwrite((char *)(&regval), sizeof(char), regWidth2Size(LEVEL_BASE::REG_XMM0), pFile);

    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_XMM1, reinterpret_cast<UINT8*>(&regval));
   fwrite((char *)(&regval), sizeof(char), regWidth2Size(LEVEL_BASE::REG_XMM1), pFile);

    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_XMM2, reinterpret_cast<UINT8*>(&regval));
   fwrite((char *)(&regval), sizeof(char), regWidth2Size(LEVEL_BASE::REG_XMM2), pFile);

    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_XMM3, reinterpret_cast<UINT8*>(&regval));
   fwrite((char *)(&regval), sizeof(char), regWidth2Size(LEVEL_BASE::REG_XMM3), pFile);

    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_XMM4, reinterpret_cast<UINT8*>(&regval));
   fwrite((char *)(&regval), sizeof(char), regWidth2Size(LEVEL_BASE::REG_XMM4), pFile);

    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_XMM5, reinterpret_cast<UINT8*>(&regval));
   fwrite((char *)(&regval), sizeof(char), regWidth2Size(LEVEL_BASE::REG_XMM5), pFile);

    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_XMM6, reinterpret_cast<UINT8*>(&regval));
   fwrite((char *)(&regval), sizeof(char), regWidth2Size(LEVEL_BASE::REG_XMM6), pFile);

    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_XMM7, reinterpret_cast<UINT8*>(&regval));
   fwrite((char *)(&regval), sizeof(char), regWidth2Size(LEVEL_BASE::REG_XMM7), pFile);

   fclose(pFile);	

//detach. so that segmentation fault will generate a core dump.	
    PIN_Detach();
//do not let the application unblock the signal	
    return FALSE;
}

INT32 GetSysArgNum(ADDRINT sys_id) {
    return sys_map[sys_id].argnum;
}

const char *GetSysName(ADDRINT sys_id) {
    return sys_map[sys_id].sysname;
}

VOID SyscallEntry(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
    ADDRINT num  = PIN_GetSyscallNumber(ctx, std);
    UINT32 argnum = GetSysArgNum(num);

    *sysout << num << "-" << argnum;
    for (UINT32 id=0; id<argnum; id++) {
        *sysout << "-" << PIN_GetSyscallArgument(ctx, std, id);
    }
    *sysout << "-" << GetSysName(num);
}

VOID SyscallExit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
    *sysout << "-" << PIN_GetSyscallReturn(ctx, std) << endl;
}

int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) {
	out = new std::ofstream(fileName.c_str());
    }

    string sysFile = KnobSysFile.Value();

    if (!sysFile.empty()) {
	sysout = new std::ofstream(sysFile.c_str());
    }

    if (KnobCount)
    {

//	PIN_UnblockSignal(11, TRUE);
	PIN_InterceptSignal(11, Intercept, 0);

        // Register function to be called to instrument traces
        INS_AddInstrumentFunction(Trace, 0);

        // Register function to be called for every thread before it starts running
//        PIN_AddThreadStartFunction(ThreadStart, 0);

        // Register function to be called when the application exits
//        PIN_AddFiniFunction(Fini, 0);
    }

    /* functions to get called on system calls */
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);
    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
