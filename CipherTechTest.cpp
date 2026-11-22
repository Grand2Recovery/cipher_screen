// CipherTechTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma once

//#include "Cipher.h"
#include "KBDreader.h"
void copy_vector(std::vector<unsigned int>& copied, std::vector<unsigned int>& copy) {
    for (auto it = copied.begin(); it != copied.end(); ++it) {
        copy.push_back(*it);
    }
}

void print_vector(std::vector<unsigned int>& my_vector, std::ofstream& logfile) {
    for (auto it = my_vector.begin(); it != my_vector.end(); ++it) {
        std::cout << *it << " ";
        logfile << *it << " ";
    }
    std::cout << "\n";
    logfile << "\n";
}

void recursive_test_all_subsets(unsigned int starting_key, unsigned int& target, unsigned int& cycles, std::vector<unsigned int>& bits_candidates, std::vector<unsigned int> subset, unsigned int index, unsigned int& target_depth, std::ofstream& logfile, std::vector<unsigned int>& output) { // return 0 if no match, otherwise return 1.
    if (index == target_depth) { // Run the FLSR cycles on the key
        unsigned char* unimportant_data = nullptr; //No encyrpting will be done so data is null. data_length is unimportant for this test too.
        Cipher test_cipher(starting_key, subset);
        print_vector(subset, logfile);

        for (unsigned int i = 0; i < cycles; i++) {//Cycle through 8 times and see if the key becomes the target key provided given.
            test_cipher.transform_key();
        }
        //std::cout << "Transformed key 8 times\n";
        if (test_cipher.get_current_key() == target) {//Got the correct XOR bits.
            std::cout << "Got the target set of bits!";
            logfile << "Got the target set of bits!";
            print_vector(subset, logfile);
            return;
        }
        return;
    }
    recursive_test_all_subsets(starting_key, target, cycles, bits_candidates, subset, index + 1, target_depth, logfile, output); // Go left. Don't add to subset
    subset.push_back(bits_candidates[index]); //Add to the subset
    recursive_test_all_subsets(starting_key, target, cycles, bits_candidates, subset, index + 1, target_depth, logfile, output); //Go right and add to the subset
}

std::vector<unsigned int> find_FLSR_xor_bits(unsigned int starting_value, unsigned int target) {
    std::ofstream logfile;
    logfile.open("Logs.txt");
    if (!logfile.is_open()) {
        std::cout << "Could not open logs file.\n";
    }
    

    unsigned int max_test_bits = (sizeof(unsigned int) * constants::bits_in_byte) - 1; // Only bits 0 to 30 can be XOR'd. Since 31 is msb
    std::vector<unsigned int> possible_bits;
    std::vector<unsigned int> test_bits;
    std::vector<unsigned int> output;
    unsigned int steps = 8;

    for (unsigned int i = 0; i < max_test_bits; i++) { // From 0 to 30
        possible_bits.push_back(i);
    }
    std::cout << "Beginning recursive search for XOR bits\n";
    recursive_test_all_subsets(starting_value, target, steps, possible_bits, test_bits, 0, max_test_bits, logfile, output);
    
    logfile.close();
    return test_bits;
}

int main()
{
    /* Coding challenge 1 - independent
    std::cout << "Hello World!\n";
    unsigned int starting_key_val = 0xFFFFFFFF;
    unsigned int target_val = 0x9243F425;
    find_FLSR_xor_bits(starting_key_val, target_val);
    std::cout << "Search all subsets\n";
    */

    // Coding challenge 2 - independent
    std::cout << "Hello World!\n";
    std::vector<unsigned int> xor_bits = { 1, 2, 3, 4 };
    const char* kdbfile = "backup.kdb";
    const char* logfile = "KBDreaderLogs.txt";

    KBDreader myKBD_reader(kdbfile, logfile, xor_bits);
    myKBD_reader.readKBD();
}


// Task 1. Implement the LSFR algorithm to be able to generate a keystream that can encrypt data.
//  1. Implement the basic function. I believe it is a Galois LFSR.
//  2. Find the tap bits for the exact algorithm implementation needed to transform  0xFFFFFFFF into 0x9243F425 after 8 progressions
//      2.1 Run all subsets of [0 - 30] through 8 progressions and see if it the target value pops up. 

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
