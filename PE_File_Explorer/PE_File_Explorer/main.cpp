#include<stdio.h>
#include<windows.h>
#include<iomanip>
#include<stdlib.h>
#include<io.h>
#include<fcntl.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<conio.h>
#include<iostream>

using namespace std;

long int OffDosHeader = 0;
long int OffFileHeader = 0;
long int OffOptHeader = 0;
long int OffSecHeader = 0;

void CalculateOffset(int fd)
{
	IMAGE_DOS_HEADER dosheader;
	_read(fd,&dosheader,sizeof(dosheader));

	OffDosHeader = 0;
	OffFileHeader = dosheader.e_lfanew + 4;
	OffOptHeader = OffFileHeader + 0x14;
	OffSecHeader = OffOptHeader + sizeof(IMAGE_OPTIONAL_HEADER);

	_lseek(fd,0,0);
}

class dos_header
{
public:
	IMAGE_DOS_HEADER dosheader;

	int fp;

	dos_header(int f)
	{
		fp=f;
		_lseek(fp,OffDosHeader,0);
		_read(f,&dosheader,sizeof(dosheader));
	}

	void show_header()
	{
		char ch;

		cout<<endl<<"-----------------DOS Header----------------------"<<endl;
		cout<<"Magic number :                      "<<std::hex<<dosheader.e_magic;
		ch = dosheader.e_magic & 0x00ff; printf("\t%c",ch); ch =0;
		ch = (dosheader.e_magic & 0xff00)>>8; printf("%c\n",ch);

		cout<<"Bytes on last page of file:         "<<dosheader.e_cblp<<endl;
		cout<<"Pages in File:                      "<<dosheader.e_cp<<endl;
		cout<<"Relocation:                         "<<dosheader.e_crlc<<endl;
		cout<<"Size of headers in paragraphs:      "<<dosheader.e_cparhdr<<endl;
		cout<<"Minimum extra paragraphs needed:    "<<dosheader.e_minalloc<<endl;
		cout<<"Maximum extra paragraphs needed:    "<<dosheader.e_maxalloc<<endl;
		cout<<"Initial (relative) SS value:        "<<dosheader.e_ss<<endl;
		cout<<"Initial SP value:                   "<<dosheader.e_sp<<endl;
		cout<<"CheckSum:                           "<<dosheader.e_csum<<endl;
		cout<<"Initial IP value:                   "<<dosheader.e_ip<<endl;
		cout<<"Initial (relative) CS value:        "<<dosheader.e_cs<<endl;
		cout<<"File address of relocation table:   "<<dosheader.e_lfarlc<<endl;
		cout<<"Overlay Number:                     "<<dosheader.e_ovno<<endl;
		cout<<"OEM identifier:                     "<<dosheader.e_oemid<<endl;
		cout<<"OEM information(e_oemid specific):  "<<dosheader.e_oeminfo<<endl;
		cout<<"RVA address of PE Header:           "<<dosheader.e_lfanew<<endl;
	}
};

class file_header
{
public:
	IMAGE_FILE_HEADER fileHeader;
	int fp;

	file_header(int f)
	{
		fp = f;
		_lseek(fp,OffFileHeader,0);
		_read(f,&fileHeader,sizeof(fileHeader));
	}

	void show_header()
	{
		cout<<endl<<"-----------------FILE Header----------------------"<<endl;
		printf("Machine:                  %x",fileHeader.Machine);
		switch(fileHeader.Machine)
		{
		case 0x014c:cout<<"\tIntel 386"<<endl;
			break;
		case 0x0162:cout<<"\tR3000-MIPS"<<endl;
			break;
		case 0x0166:cout<<"\tR4000-MIPS"<<endl;
			break;
		case 0x0168:cout<<"\tR10000-MIPS"<<endl;
			break;
		case 0x0169:cout<<"\tMIPS WCE v2"<<endl;
			break;
		case 0x0184:cout<<"\tAlpha_AXP"<<endl;
			break;
		case 0x01a2:cout<<"\tSH3"<<endl;
			break;
		case 0x01a3:cout<<"\tSH3DSP"<<endl;
			break;
		case 0x01a4:cout<<"\tSH3E"<<endl;
			break;
		case 0x01a6:cout<<"\tSH4"<<endl;
			break;
		case 0x01a8:cout<<"\tSH5"<<endl;
			break;
		case 0x01c0:cout<<"\tARM"<<endl;
			break;
		case 0x01c2:cout<<"\tARM thumb"<<endl;
			break;
		case 0x01d3:cout<<"\tARM AM33"<<endl;
			break;
		case 0x01f0:cout<<"\tIBM PowerPC"<<endl;
			break;
		case 0x01f1:cout<<"\tIBM PowerPC FP"<<endl;
			break;
		case 0x0200:cout<<"\tIntel64"<<endl;
			break;
		case 0x0266:cout<<"\tMIPS16"<<endl;
			break;
		case 0x0366:cout<<"\tMIPSFPU"<<endl;
			break;
		case 0x0466:cout<<"\tMIPSFPU16"<<endl;
			break;
		case 0x0284:cout<<"\tALPHA64"<<endl;
			break;
		case 0x0520:cout<<"\tInfineon Tricore"<<endl;
			break;
		case 0x0cef:cout<<"\tInfineon CEF"<<endl;
			break;
		case 0x0ebc:cout<<"\tEFI Byte Code"<<endl;
			break;
		case 0x8664:cout<<"\tAMD64(kb)"<<endl;
			break;
		case 0x9041:cout<<"\tM32R"<<endl;
			break;
		case 0xc0ee:cout<<"\tCEE"<<endl;
			break;
		default:break;
		}
		cout<<"Number of sections:       "<<fileHeader.NumberOfSections<<endl;
		cout<<"Time Date Stamp:          "<<fileHeader.TimeDateStamp<<endl;
		cout<<"Pointer to symbol table:  "<<fileHeader.PointerToSymbolTable<<endl;
		cout<<"Number of symbols:        "<<fileHeader.NumberOfSymbols<<endl;
		cout<<"Size of optional Header:  "<<fileHeader.SizeOfOptionalHeader<<endl;
		printf("Characteristics:          %x\n",fileHeader.Characteristics);
		char charac[16][100]={"Relocation info stripped from file","File is executable","Line numbers stripped from file","Local symbols stripped from file","Agressively trim working set"," "," ","Bytes of machine words are reversed(low)","32bit word machine","Debug info stripped from file into .DBG file","Image is on removable media copy on swap and execute","Image is on NET copy and run from swap file","System File","File is DLL","File should be run on UP machine","Bytes of machine words are reversed(high)"};
		int i=0,mask=0x0001;
		while(i<16)
		{
			if((fileHeader.Characteristics & mask) == mask)
			{
				cout<<"\t"<<charac[i]<<endl;
			}

			i++;
			mask = mask * 2;
		}
	}
};

class opt_header
{
public:
	IMAGE_OPTIONAL_HEADER optHeader;
	int fp;

	opt_header(int f)
	{
		fp = f;
		_lseek(fp,OffOptHeader,0);
		_read(f,&optHeader,sizeof(optHeader));
	}

	void show_header()
	{
		cout<<endl<<"--------------------OPTIONAL HEADER INFO------------------"<<endl;
		cout<<"Magic:                     "<<optHeader.Magic<<endl;
		cout<<"Size of Code:              "<<optHeader.SizeOfCode<<endl;
		cout<<"Size of initialized data:  "<<optHeader.SizeOfInitializedData<<endl;
		cout<<"Size of uninitialized data:"<<optHeader.SizeOfUninitializedData<<endl;
		cout<<"Address of Entry Point:    "<<optHeader.AddressOfEntryPoint<<endl;
		cout<<"Base of Code:              "<<optHeader.BaseOfCode<<endl;
		cout<<"Base of Data:              "<<optHeader.BaseOfData<<endl;
		cout<<"IMAGE BASE:                "<<optHeader.ImageBase<<endl;
		cout<<"Section Allignment:        "<<optHeader.SectionAlignment<<endl;
		cout<<"File Allignment:           "<<optHeader.FileAlignment<<endl;
		cout<<"Major Operating System Version: "<<optHeader.MajorOperatingSystemVersion<<endl;
		cout<<"Minor Operating System Version: "<<optHeader.MinorOperatingSystemVersion<<endl;
		cout<<"Major Image Version:       "<<optHeader.MajorImageVersion<<endl;
		cout<<"Minor Image Version:       "<<optHeader.MinorImageVersion<<endl;
		cout<<"Major Subsystem Version:   "<<optHeader.MajorSubsystemVersion<<endl;
		cout<<"Minor Subsystem Version:   "<<optHeader.MinorSubsystemVersion<<endl;
		cout<<"Size of Image:			  "<<optHeader.SizeOfImage<<endl;
		cout<<"Size of Headers:           "<<optHeader.SizeOfHeaders<<endl;
		cout<<"CheckSum:				  "<<optHeader.CheckSum<<endl;
		cout<<"Subsystem:                 "<<optHeader.Subsystem<<endl;
		cout<<"Dll Characteristics:       "<<optHeader.DllCharacteristics<<endl;
		cout<<"Size of Stack Reserve:     "<<optHeader.SizeOfStackReserve<<endl;
		cout<<"Size of Stack Commit:      "<<optHeader.SizeOfStackCommit<<endl;
		cout<<"Size of Heap Reserve:      "<<optHeader.SizeOfHeapReserve<<endl;
		cout<<"Size of Heap Commit:       "<<optHeader.SizeOfHeapCommit<<endl;
		cout<<"Loader Flags:             "<<optHeader.LoaderFlags<<endl;
		cout<<"Number of Rva and Sizes:   "<<optHeader.NumberOfRvaAndSizes<<endl;
	}
};

class sec_header
{
public:
	IMAGE_SECTION_HEADER secHeader;
	int NoOfSec;
	int fp;

	sec_header(int f)
	{
		IMAGE_FILE_HEADER fileHeader;
		fp=f;
		_lseek(fp,OffFileHeader,0);
		_read(f,&fileHeader,sizeof(fileHeader));
		NoOfSec = fileHeader.NumberOfSections;

		_lseek(f,OffSecHeader,0);
		_read(f,&secHeader,sizeof(secHeader));
	}

	void show_header()
	{
		cout<<endl<<"---------------------SECTION HEADER INFO--------------"<<endl;
		while (NoOfSec != 0)
		{
			cout<<"Name:                    "<<secHeader.Name<<endl;
			cout<<"Virtual Address:         "<<secHeader.VirtualAddress<<endl;
			cout<<"Size Of Raw Rata:        "<<secHeader.SizeOfRawData<<endl;
			cout<<"Pointer To Raw Data:     "<<secHeader.PointerToRawData<<endl;
			cout<<"Pointer To Relocations:  "<<secHeader.PointerToRelocations<<endl;
			cout<<"Pointer To Line numbers: "<<secHeader.PointerToLinenumbers<<endl;
			cout<<"Number Of Relocations:   "<<secHeader.NumberOfRelocations<<endl;
			cout<<"Number Of Line Numbers:  "<<secHeader.NumberOfLinenumbers<<endl;
			cout<<"Characteristics:         "<<secHeader.Characteristics<<endl;
			NoOfSec--;
			cout<<endl<<"--------------------------------------------------------"<<endl;

			_read(fp,&secHeader,sizeof(secHeader));
		}
	}
};

int main(int argc,char *argv[])
{
	int ip;
	char file_name[100];

	cout<<endl<<"Enter name of file"<<endl;
	cin>>file_name;
	
	int fd=_open("F:\\New folder\\iTunesSetup.exe",O_BINARY,_S_IREAD);
	if(fd == -1)
	{
		cout<<endl<<"Error: File not Found"<<endl;
		return-1;
	}

	CalculateOffset(fd);

	do
	{
		ip = 0;

		cout<<endl<<"Enter your choice"<<endl;
		cout<<"1.DOS Header"<<endl;
		cout<<"2.File Header"<<endl;
		cout<<"3.Optional Header"<<endl;
		cout<<"4.Section Header"<<endl;
		cout<<"5.Exit"<<endl;
		cout<<"Your choice ";
		cin>>ip;

		switch (ip)
		{
		case 1:
			{
				dos_header dh(fd);
				dh.show_header();
				break;
			}
		case 2:
			{
				file_header fh(fd);
				fh.show_header();
				break;
			}
		case 3:
			{
				opt_header oh(fd);
				oh.show_header();
				break;
			}
		case 4:
			{
				sec_header sh(fd);
				sh.show_header();
				break;
			}
		case 5:
			{
				_close(fd);
				exit(0);
				break;
			}
		default:
			break;
		}
	}while(ip != 5);

		return 0;
}