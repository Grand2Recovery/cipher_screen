#include "KBDreader.h"

void KBDreader::log_this(std::string line, bool endline = true) { // reused and modified code from https://en.cppreference.com/cpp/utility/variadic/va_arg
	this->logfile << line;
	if (this->print_to_screen) {
		std::cout << line;
		if (endline){
			std::cout << '\n';
		}
	}
	if (endline) {
		this->logfile << '\n';
	}
	this->logfile.flush();
}

long int KBDreader::get_file_size(const char* filename) {

	FILE* kbd_ptr = fopen(filename, "rb");
	std::string warning_message = "Could not open file %s for reading\n";
	warning_message += filename;
	if (!kbd_ptr) {
		this->log_this(warning_message);
		return -1;
	}
	fseek(kbd_ptr, 0L, SEEK_END);
	return ftell(kbd_ptr); //Returning size in bytes
}


int get_little_endian_int(char* buffer, unsigned int offset, unsigned int num_bytes) {
	int uint = 0;
	for (unsigned int j = num_bytes; j > 0; j--) {
		uint = uint << 8;
		uint = uint | buffer[offset + j - 1];
	}
	return uint;
	}

entry get_entry(char* buffer, unsigned int offset) {
	entry myentry;
	myentry.block_list_ptr = get_little_endian_int(buffer, offset, sizeof(int));
	strcpy(myentry.name, buffer);
	return myentry;
}

int KBDreader::verify_header() {
	this->log_this("Checking if KBD Header is correct");
	KBD_Header myKBD = *(KBD_Header*)this->KBD_contents;
	for (unsigned int i = 0; i < this->KBD_signature_length; i++) {
		if (myKBD.signature[i] != this->KBD_signature[i]) {
			this->log_this("KBD Header is incorrect");
			exit;
			return 0;
		}
	}
	//Extract the byte number for the start of the entry list byte by byte. lsb first read
	myKBD.entry_list_ptr = get_little_endian_int(this->KBD_contents, this->KBD_signature_length,sizeof(unsigned int));
	this->log_this("Entry list begins on " + std::to_string(myKBD.entry_list_ptr));
	return myKBD.entry_list_ptr; //
}


int KBDreader::navigate_block(block myblock) {
	std::string warning_message = "Size ";
	warning_message += std::to_string(myblock.size);
	this->log_this(warning_message);
	warning_message = "data pointer " + std::to_string(myblock.data_ptr);
	this->log_this(warning_message);

	char* data = (char*)this->KBD_contents + myblock.data_ptr; // if this fails just use a for loop using ++
	for (int i = 0; i < myblock.size; i++) {
		warning_message = "";
		warning_message += this->KBD_cipher->Crypt_byte(data[i]);
		this->log_this(warning_message, false); //iterate through the data and provide decoded data
	}
	this->log_this("\n");
	return 1;
}

bool blocklist_end(char* cur_block, int endvalue) {
	int check = (int)* cur_block;
	if (check == endvalue) {
		return true;
	}
	return false;
}

block get_block(char* myptr) {
	block my_block;
	my_block.size = get_little_endian_int(myptr, 0, sizeof(short));
	my_block.data_ptr = get_little_endian_int(myptr, sizeof(short), sizeof(int));
	return my_block;
}

int KBDreader::navigate_blocklist(char* myptr) {
	std::string warning_message = "block ";
	for (int i = 0; i < this->max_blocks; i++) {
		if (blocklist_end(myptr, this->list_ending)) {
			this->log_this("Iterated through the entire block list");
			return 1;
		}
		this->log_this(warning_message + std::to_string(i));
		this->navigate_block(get_block(myptr));
		myptr += sizeof(this->sizeof_block); // should be 6. keep an eye on this
	}
	this->log_this("KBD file is corrupted. Exceeded max number of blocks in a list possible");
	return 0;
}

int KBDreader::iterate_through_entry_list(char* myptr) { //<-----call navigate_block
	std::string warning_message = "";
	for (int i = 0; i < this->max_entries; i++) {
		warning_message = "";
		if ((int)myptr == this->list_ending) {
			this->log_this("Iterated through the entire entry list");
			return 1;
		}
		entry my_entry = get_entry(myptr, this->max_entry_name_length);
		warning_message += "Entry ";
		warning_message += std::to_string(i);
		warning_message += " Name: ";
		warning_message += my_entry.name;
		this->log_this(warning_message);
		this->navigate_blocklist(this->KBD_contents + my_entry.block_list_ptr);
		myptr += this->sizeof_entry;
	}
	this->log_this("KBD file is corrupted. Exceeded max number of entries possible");
	return 0;
}

int KBDreader::readKBD() { // return 1 on success. 0 on failure
	//verify signature in header
	//--------------entry* myptr = (entry*)(this->KBD_contents + this->verify_header());
	char* myptr = this->KBD_contents + this->verify_header(); // I need to replace the kbd data structures with just plain character pointer manipulation
	//go to the entry list
	return this->iterate_through_entry_list(myptr);

	//start iterating through the entry list. If don't find the list ending before reading 128 entries send error
		//log/print name of the entry
		//go to blocks list

			//iterate over blocks. Send a warning if no list end is found after 255th index
				//print/log block size. Go to block

					//print/log the raw data after decrypting it with FSLR
}
//return 1 upon success. Return 0 otherwise 
	// Note: Only the data is FSLR encrypted. All other structures are not
	//Failures include
	// 0. The file can't be opened.
	// If the issues below do occur then the file is corrupted in some way
	// 1. The first six bytes are not "CT2018"
	// 2. The entry list has more than 128 entries. Meaning OxFFFFFFFF is not encountered after the 128th iteration through single entries
	// 3. The block list having more than255 entries. Meaning OxFFFFFFFF is not encountered after the 255th iteration through single entries
	// 4. Nullptrs in general


KBDreader::KBDreader(const char* KBDfilename, const char* logfilename, std::vector<unsigned int> fslr_xor_bits)
{
	this->KBDfile.assign(KBDfilename);
	this->logfile_name.assign(logfilename);

	logfile.open(this->logfile_name);
	if (!logfile.is_open()) {
		std::cout << "Could not open logs file " << this->logfile_name << "\n";
	}

	FILE* kbd_ptr = fopen(this->KBDfile.c_str(), "rb");
	if (!kbd_ptr) {
		std::cout << "Could not open KBD file " << KBDfilename << " for reading\n";
	}

	//allocate a buffer for the file contents.
	long int kbd_file_size = get_file_size(this->KBDfile.c_str());
	this->KBD_contents = (char*)malloc(kbd_file_size + 1);
	if (this->KBD_contents == nullptr) {
		std::cout << "Error: Could not malloc buffer to store kbd contents\n";
	}
	fread(this->KBD_contents, kbd_file_size, 1, kbd_ptr);

	this->KBD_cipher= new Cipher(0xFFFFFFFF, fslr_xor_bits);
}


KBDreader::~KBDreader()
{
	this->logfile.close();
	free(this->KBD_contents);
	delete this->KBD_cipher;
}
