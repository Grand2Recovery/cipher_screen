#pragma once
#pragma warning(disable : 4996)

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <string>

namespace constants {
	const unsigned int bits_in_byte = 8;
}

class Cipher
{
public:
	Cipher(unsigned int initial_value, std::vector<unsigned int> critical_bits);
	~Cipher();

	unsigned int get_current_key();

	char* Crypt(unsigned int data_length, char* data); // Encrypt/Decrypt a variable length piece of data
	char Crypt_byte(char data); // Does not reset key after encrypt/decrypting

	unsigned int transform_key();

	const int key_length = 32; // Change if data type of key changes
private:
	unsigned int initial_value;	// The key that will be alogorithmically altered during encryption. Key is 32 bit
	unsigned int current_key_value;	// Current state of the encryption key

	char* data = nullptr;		// The data that will be encrypted and decrypted

	unsigned int zero_bit_filter; // Will be all bits set to 0 but 0th by constructor

	std::vector<unsigned int> critical_bits;	// The bits that will be used for the LSFR key transformation from 0 to 32 

};

