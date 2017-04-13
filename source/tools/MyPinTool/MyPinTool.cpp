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

#define THRESHOLD 100000

/* ================================================================== */
// Global variables 
/* ================================================================== */

UINT64 insCount = 0;        //number of dynamically executed instructions
UINT64 threadCount = 0;     //total number of threads, including main thread

std::ostream * out = &cerr;
std::ostream * sysout = &cerr;
std::ostream * mapout = &cerr;

std::stringstream ss;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
		"o", "", "specify file name for MyPinTool output");

KNOB<string> KnobSysFile(KNOB_MODE_WRITEONCE,  "pintool",
		"sys", "", "specify file name for logging arguments for system call");

KNOB<string> KnobMapFile(KNOB_MODE_WRITEONCE,  "pintool",
		"map", "", "specify file name for logging maps of address space");

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


const char * dumpInstructions(INS ins)
{

	std::stringstream ssl; 
	ssl << INS_Disassemble(ins);
	return strdup(ssl.str().c_str());

}

std::list<REG> * listRegisters(INS ins)
{

	std::list<REG> * registers = new std::list<REG>;

	for (UINT i = 0; i < INS_OperandCount(ins); i++){

		if(INS_OperandIsReg(ins, i)){
			REG reg = INS_OperandReg(ins, i);
			registers->push_back(reg);
		}
	}

	return registers; 
}

std::list<REG> * listMemRegisters(INS ins)
{

	std::list<REG> * registers = new std::list<REG>;

	for (UINT i = 0; i < INS_OperandCount(ins); i++){

		if(INS_OperandIsMemory(ins, i)){

			if (REG_valid(INS_OperandMemoryBaseReg(ins, i))) {
				registers->push_back(INS_OperandMemoryBaseReg(ins, i));
			}

			if (REG_valid(INS_OperandMemoryIndexReg(ins, i))) {
				registers->push_back(INS_OperandMemoryIndexReg(ins, i));
			}

			if (INS_OperandMemorySegmentReg (ins, i) == REG_SEG_GS) {
				registers->push_back(REG_SEG_GS_BASE);
			}
		}
	}

	return registers;
}


UINT regWidth2Size(REG reg)
{
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


VOID LogInstDetail_Sim(THREADID threadID, ADDRINT address, const CONTEXT *ctx, const char *disasm) {
	// count inst number
	insCount++;

	INT pid = PIN_GetPid();
	
	ss << std::hex << pid << "-" << threadID << "-" << address << "-" << disasm << endl;

	if (insCount % THRESHOLD == 0) {
		*out << ss.rdbuf() << std::flush;
		ss.str("");
	}
}


VOID LogInstDetail_Com(THREADID threadID, ADDRINT address, const CONTEXT *ctx, const char* disasm, void * regdata, void *memdata)
{
	REG reg;
	std::string name;
	PIN_REGISTER regval; 

	// count inst number
	insCount++;

	std::list<REG> * registers = (std::list<REG> *)regdata;

	std::list<REG> * memreg = (std::list<REG> *)memdata;

	INT pid = PIN_GetPid();
	
	ss << std::hex << pid << "-" << threadID << "-" << address << "-" << disasm;

	// fixme later: optimization for merging two list into one 
	for(std::list<REG>::iterator it = registers ->begin(); it != registers->end(); it++){
		ss << "-OR";

		reg = (*it);
		name = REG_StringShort(reg);
		ss << name.c_str() << ":";

		PIN_GetContextRegval(ctx, reg, reinterpret_cast<UINT8*>(&regval));

		ss << std::hex << Val2Str(&regval, regWidth2Size(reg));
	}


	for(std::list<REG>::iterator it = memreg ->begin(); it != memreg->end(); it++){
		ss << "-OM";

		reg = (*it);
		name = REG_StringShort(reg);
		ss << name.c_str() << ":";

		PIN_GetContextRegval(ctx, reg, reinterpret_cast<UINT8*>(&regval));

		ss << std::hex << Val2Str(&regval, regWidth2Size(reg));
	}

	ss << endl;

	if (insCount % THRESHOLD == 0) {
		*out << ss.rdbuf() << std::flush;
		ss.str("");
	}
}


BOOL IsLogRegInfo(INS ins) {

	if (INS_IsBranch(ins)) return false;

	const char * mnemonic = INS_Mnemonic(ins).c_str();
	if (strcmp("TEST", mnemonic) == 0) {
		return false;
	}

	if (strcmp("CMP", mnemonic) == 0) {
		return false;
	}

	if (strcmp("NOP", mnemonic) == 0) {
		return false;
	}

	return true;
}

VOID Trace(INS ins,  VOID *v)
{

	if (IsLogRegInfo(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogInstDetail_Com, IARG_THREAD_ID, IARG_INST_PTR, IARG_CONTEXT, IARG_PTR, dumpInstructions(ins), IARG_PTR, (void*)listRegisters(ins), IARG_PTR, (void*)listMemRegisters(ins), IARG_END);
	} else {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogInstDetail_Sim, IARG_THREAD_ID, IARG_INST_PTR, IARG_CONTEXT, IARG_PTR, dumpInstructions(ins), IARG_END);
	}
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
	cerr << "Only be invoked with signal unlocked\n" << endl;
	*out << ss.rdbuf() << std::flush;
	ss.str("");
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */


BOOL Intercept(THREADID, INT32 sig, CONTEXT *ctx, BOOL, const EXCEPTION_INFO *, VOID *)
{
	std::cerr << "Instruction Count: " << insCount << std::endl;
	std::cerr << "Intercepted signal " << sig << std::endl;

	*out << ss.rdbuf() << std::flush;
	ss.str("");

	//detach. so that segmentation fault will generate a core dump.	
	PIN_Detach();
	//do not let the application unblock the signal	
	return FALSE;
}

INT32 GetSysArgNum(ADDRINT sys_id)
{
	return sys_map[sys_id].argnum;
}

const char *GetSysName(ADDRINT sys_id)
{
	return sys_map[sys_id].sysname;
}

VOID SyscallEntry(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{

	ADDRINT argval;

	ADDRINT num  = PIN_GetSyscallNumber(ctx, std);

	UINT32 argnum = GetSysArgNum(num);

	*sysout << std::hex << Val2Str(&num, 4);
	*sysout << "-";
	*sysout << std::hex << argnum;

	for (UINT32 id=0; id<argnum; id++) {
		argval = PIN_GetSyscallArgument(ctx, std, id);
		*sysout << "-" << std::hex << Val2Str(&argval, 4);
	}
	//*sysout << "-" << GetSysName(num);
}


VOID SyscallExit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{

	ADDRINT retval =  PIN_GetSyscallReturn(ctx, std);
	*sysout << "-" << std::hex << Val2Str(&retval, 4) << endl;
}


void library_unloaded_function(IMG image, void* arg)
{
        //*mapout << "Unloading " << IMG_Name(image) << endl;
}


void library_loaded_function(IMG image, void* arg)
{
        *mapout << IMG_Name(image) << " ";
        *mapout << hex << IMG_LowAddress(image) << " ";
        *mapout << IMG_HighAddress(image) << endl;
/*
        UINT32 num_of_region = IMG_NumRegions(image);

        for (UINT32 i = 0; i < num_of_region; i++) {
                *mapout << "Region " << i << endl;
                *mapout << "Low:" << IMG_RegionLowAddress(image, i) << "|";
                *mapout << "High:" << IMG_RegionHighAddress(image, i) << endl;
        }
*/
}



int main(int argc, char *argv[])
{
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid 
	if( PIN_Init(argc,argv) ) {
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

	string mapFile = KnobMapFile.Value();

	if (!mapFile.empty()) {
		mapout = new std::ofstream(mapFile.c_str());
	}

	ss.str("");

	//	PIN_UnblockSignal(11, TRUE);
	PIN_InterceptSignal(11, Intercept, 0);

	// Register function to be called to instrument traces
	INS_AddInstrumentFunction(Trace, 0);

	/* functions to get called on system calls */
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);

	/* functions to get called on library loading */
        IMG_AddInstrumentFunction(library_loaded_function, 0);
        IMG_AddUnloadFunction(library_unloaded_function, 0);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	cerr << "Pid " << std::hex << PIN_GetPid() << endl;

	cerr <<  "===============================================" << endl;
	cerr <<  "This application is instrumented by MyPinTool" << endl;

	if (!KnobOutputFile.Value().empty()) {

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
