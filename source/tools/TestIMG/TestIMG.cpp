#include <stdio.h>
#include <iostream>
#include <fstream>
#include "pin.H"
 
ofstream out;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "testimg.out", "specify all the address range of img");


void library_unloaded_function(IMG image, void* arg)
{
	out << "Unloading " << IMG_Name(image) << endl;
}

void library_loaded_function(IMG image, void* arg)
{
	out << "Loading " << IMG_Name(image) << endl;
	out << "Name:" << IMG_Name(image) << " | ";
	//out << "Type : " << img_type_to_string(IMG_Type(image)) << " | ";
	//out << "Strt : " << hex << IMG_StartAddress(image) << " | ";
	out << "Low:" << hex << IMG_LowAddress(image) << " | ";
	out << "High:" << hex << IMG_HighAddress(image) << endl;
	//out << "Enty : " << hex << IMG_Entry(image) << " | ";
	//out << "Mapd:" << hex << IMG_SizeMapped(image) << endl;
	
	UINT32 num_of_region = IMG_NumRegions(image);

	for (UINT32 i = 0; i < num_of_region; i++) {
		out << "Region " << i << endl;
		out << "Low:" << IMG_RegionLowAddress(image, i) << "|";
		out << "High:" << IMG_RegionHighAddress(image, i) << endl;
	}
}


VOID Fini(INT32 code, VOID *v) {
	out.setf(ios::showbase);
	out.close();
}

INT32 Usage() {
	cerr << "This tool logs all the mapping libraries" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

int main(int argc, char * argv[]) {

        if (PIN_Init(argc, argv))
		return Usage();

        out.open(KnobOutputFile.Value().c_str(), ios::out);
 
	IMG_AddInstrumentFunction(library_loaded_function, 0);
        IMG_AddUnloadFunction(library_unloaded_function, 0);

        PIN_AddFiniFunction(Fini, 0);
        PIN_StartProgram();
        return 0;
}
