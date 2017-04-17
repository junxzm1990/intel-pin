#!/usr/bin/python

import os
import sys

RegIdDict = {"eax" : 1, "ecx": 2, "edx": 3, "ebx": 4, "esp":5, "ebp":6, "esi":7, "edi":8, "ax":9, "cx":10, "dx":11, "bx":12, "sp":13, "bp":14, "si":15, "di":16, "al":17, "cl":18, "dl":19, "bl":20, "ah":21, "ch":22, "dh":23, "bh":24, "mm0":25, "mm1": 26, "mm2": 27, "mm3":28, "mm4":29, "mm5":30, "mm6":31, "mm7":32, "xmm0":33, "xmm1":34, "xmm2":35, "xmm3":36, "xmm4":37, "xmm5":38, "xmm6":39, "xmm7":40, "eflags":81, "eip":85, "es":65, "cs":66, "ss":67, "ds":68, "fs":69, "gs":70, "seg_gs_base":70, "st0":73, "st1":74}

SysCallRegs = [1, 4, 2, 3, 7, 8, 6]

def parse_regs(reginfo):

	#print reginfo

	regs = {}
	for item in reginfo:
		if item.find("invalid") != -1:
			continue

		if item.find("OM") == -1 and item.find("OR") == -1:
			continue;

		regval = item.split(":")
		if RegIdDict[regval[0][2:]] not in regs:
			val = regval[1][2:]
			
			if len(val) % 2:
				val = "0x0" + val
			else:
				val = regval[1]

			regs[RegIdDict[regval[0][2:]]] = val
	return regs

# format of sysinfo
# syscall num - arguments num - arguments... - syscallname -return value
def parse_sysargs(sysinfo):

	regs = {}

	syslogs = sysinfo.split("-")

	regs[SysCallRegs[0]] = syslogs[0]
	
	argnum = int(syslogs[1])
	
	for index, args in enumerate(syslogs[2:]) :
		if index < argnum :
			regs[SysCallRegs[1+index]] =  args
	
	return regs, syslogs[argnum+2]

def is_syscall(inst) :
	return inst.startswith('sysenter') or inst.startswith('int')

def parse_file(logpath, instpath, regpath, syslogpath):
	
	syslog = []
	syscount = 0

	# small file, directly read the whole into memory
	with open(syslogpath, "r") as fd:
		syslog = fd.read().split("\n")

	with open(logpath, "r") as fl, open(instpath, "w") as fi, open(regpath, "w") as fr:
		for line in fl:
			if not len(line):
				break;

			items = line.rstrip().split("-")	

			fi.write(items[2]+"\n")

			if len(items) >= 5:

				if is_syscall(items[3]) :
					regdict, retval = parse_sysargs(syslog[syscount])
					syscount += 1
					regval = "1:" + retval + ";"
				else :
					regdict = parse_regs(items[4:])
					regval = ""

				if len(regdict) == 0:
					regval = "noreg"
				else:
					regval += ";".join([str(reg)+":" + regdict[reg] for reg in regdict])
			else:
				regval = "noreg"

			fr.write(regval + "\n")

#do the parse
if __name__ == "__main__":

	if len(sys.argv) != 5 :
		print "Usage: provide four arguments, log by intel pin, inst, reg, syscall\n"

	parse_file(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
