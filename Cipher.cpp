#include "Cipher.h"

unsigned int Cipher::get_current_key() {
	return this->current_key_value;
}


Cipher::Cipher(unsigned int initial_value, std::vector<unsigned int> critical_bits)
{
	this->initial_value = initial_value;
	this->current_key_value = initial_value;
	
	// Have to verify all values are below 32 and size is below 32. Since key is 32 bits
	//this->critical_bits = critical_bits;
	for (unsigned int i = 0; i < critical_bits.size(); i++) {
		if (critical_bits[i] < (sizeof(unsigned int) * constants::bits_in_byte) - 2 ) { //The most significant bit can't be XOR by 0th bit and the next greater bit
			this->critical_bits.push_back(critical_bits[i]);
		}
	}
	this->critical_bits.reserve(this->critical_bits.size());

	this->zero_bit_filter = 1;

}

unsigned int Cipher::transform_key() {
	unsigned int filter = 0;
	// 1. Check the 0th bit to see if it is 1. If so, add 2 ^ (sizeof key - 1)
	if (this->current_key_value & this->zero_bit_filter) {
		filter += (unsigned int)pow(2, this->key_length - 1);
	}
	// 2. Iterate through every critical bit. These will be affected by XOR operations between 0th bit and preceding bits.
	// 2.1 Construct the filter based on the critical bits and the bits and the state of the bits they map to.
	for (unsigned int i = 0; i < this->critical_bits.size(); i++) {
		filter+= (unsigned int)pow(2, this->critical_bits[i]);
	}
	// 3. Shift the bits of the last state by one and XOR it with the mask
	this->current_key_value = (this->current_key_value >> 1) ^ filter;
	return this->current_key_value;
}

Cipher::~Cipher()
{
}

char* Cipher::Crypt(unsigned int data_length, char* data) {
	for (int i = 0; i < data_length; i++) {
		data[i] = data[i] ^ this->current_key_value;
		this->transform_key();
	}
	this->current_key_value = this->initial_value;
	return 0;
}

char Cipher::Crypt_byte(char byte) {
	char output = byte ^ this->current_key_value;
	this->transform_key();
	return output;
	
}