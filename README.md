# intel-pt

Intel Pin application to trace executed instructions and the values of registers used in each instruction (base and index registers for memory accesses are also included)

# Prerequirement

- Download source code of Intel PT;
- Replace source/tools/MyPinTool/MyPinTool.cpp of the native Pin with the one in this repo;
- Copy source/tools/MyPinTool/syscallent.h to directory of native Pin;

# Build

- ia32 architecture

```
cd source/tools/MyPinTool/;
make all TARGET=ia32
```

- intel64 architecure

```
cd source/tools/MyPinTool/;
make all TARGET=intel64
```

# Run

```
cd  ~/pin-3.2-81205-gcc-linux/source/tools/MyPinTool

../../../pin -t obj-ia32/MyPinTool.so -o latex2rtf.log -sys sys.log -map maps -- ~/testcases/latex2rtf-1.9.15/latex2rtf ~/testcases/latex2rtf-1.9.15/poc.tex

 - ~/pin-3.2-81205-gcc-linux/ - path of pin executable;
 - test.log - records the execution traces and value of registers;
 - sys.log  - records syscall num and arguments of the program;
 - maps     - records memory layout of the program;
```

```
./parse.py latex2rtf/latex2rtf.log latex2rtf/instructions latex2rtf/reginfo latex2rtf/sys.log

 - latex2rtf/latex2rtf.log : Read
 - latex2rtf/instructions  : Write
 - latex2rtf/reginfo       : Write
 - latex2rtf/sys.log       : Read
```
