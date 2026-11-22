#pragma once
#include "Cipher.h"

struct KBD_Header
{
	char signature[6]; //Not null terminated!
	unsigned int entry_list_ptr;
};

struct  entry
{
	char name[16]; //Null terminated
	unsigned int block_list_ptr;
};

struct block
{
	unsigned short size;
	unsigned int data_ptr;
};

class KBDreader
{
public:
	KBDreader(const char* filename, const char* KBDreaderLogname, std::vector<unsigned int> fslr_xor_bits);
	~KBDreader();

	void log_this(std::string line, bool endline);
	int readKBD();
	long int get_file_size(const char* filename);
	int verify_header();
	int iterate_through_entry_list(char* entry_list_ptr);
	int navigate_blocklist(char* blocklist);
	int navigate_block(block myptr);

private:
	std::string KBDfile; // "store.kdb";
	std::string logfile_name;// "KBDreaderLogs.txt";

	char* KBD_contents = nullptr;
	std::ofstream logfile;

	const unsigned int max_entries = 128;
	const unsigned int max_blocks = 256;
	const unsigned int list_ending = 0xFFFFFFFF;
	const char KBD_signature[7] = "CT2018";
	const unsigned int KBD_signature_length = 6;
	const unsigned int max_entry_name_length = 16;
	const unsigned int sizeof_block = 6; //Each block is composed of a 16 bit short and 32 bit int
	const unsigned int sizeof_entry = 20; // Each entry is 16 1 byte chars (not all used) and 32 bit int 

	Cipher* KBD_cipher = nullptr;

	bool print_to_screen = true;
};

