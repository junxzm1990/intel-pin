#include <stdio.h>
#include <iostream>
#include <fstream>
#include "pin.H"
#include "syscallent.h"
 
ofstream out;

INT32 GetSysArgNum(ADDRINT sys_id) {
	return sys_map[sys_id].argnum;
}

const char *GetSysName(ADDRINT sys_id) {
	return sys_map[sys_id].sysname;
}

VOID SyscallEntry(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
        ADDRINT num  = PIN_GetSyscallNumber(ctx, std);
	UINT32 argnum = GetSysArgNum(num);
    	out << num << "-" << argnum;
	for (UINT32 id=0; id<argnum; id++) {
		out << "-" << PIN_GetSyscallArgument(ctx, std, id);
	}
	out << "-" << GetSysName(num);
}
 
VOID SyscallExit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
        out << "-" << PIN_GetSyscallReturn(ctx, std) << endl;
}
 
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "testsys.out", "specify output file name");

VOID Fini(INT32 code, VOID *v) {
        out.setf(ios::showbase);
        out.close();
}
 
INT32 Usage() {
        cerr << "This tool logs all the system calls" << endl;
        cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
        return -1;
}
 
int main(int argc, char * argv[]) {
        if (PIN_Init(argc, argv)) return Usage();
        out.open(KnobOutputFile.Value().c_str(), ios::out | ios::app);
 
	/* format of sys.log file
	 * syscall num - argnum - args ... - syscall name - return value
	 */
        /* functions to get called on system calls */
        PIN_AddSyscallEntryFunction(SyscallEntry, 0);
        PIN_AddSyscallExitFunction(SyscallExit, 0);
 
        PIN_AddFiniFunction(Fini, 0);
        PIN_StartProgram();
        return 0;
}
