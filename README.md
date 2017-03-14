# intel-pt

Intel Pin application to trace executed instructions and the values of registers used in each instruction (base and index registers for memory accesses are also included)

# Prerequirement

- Download source code of Intel PT
- Replace source/tools/MyPinTool/MyPinTool.cpp of the native Pin with the one in this repo. 

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
../../../pin -t obj-ia32/MyPinTool.so -o test.log -- /bin/ls
```
