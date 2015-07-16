/* Copyright 2015 Henry Elliott

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */
/* Note this software depends on the LGPL GMP library, and is licensed
   Permissively under the dynamic linking exception. */
/* Implementation of this:
http://www.ee.washington.edu/research/nsl/papers/jucs.pdf
*/
#include <cstdint>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdlib>
#include <string>
#include <gmp.h>

using std::vector;
using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::size_t;
using std::uint_least64_t;


int encrypt(ifstream &plaintext_file, ifstream &key_file,
            ofstream &ciphertext_file);

int decrypt(ifstream &ciphertext_file, ifstream &key_file,
            ofstream &plaintext_file);

uint_least64_t read_key(vector<unsigned char> &enc_key_vec,
                        vector<unsigned char> &auth_key_vec,
                        ifstream &key_file);


uint_least64_t largest_exponent(uint_least64_t file_length);

void set_prime(mpz_t p, uint_least64_t exponent);

void write_array(ofstream &out_file, const unsigned char *array,
                 size_t array_size, uint_least64_t half_key_length, bool decryption);

ifstream::pos_type get_length(ifstream &file);

int bit_mask(uint_least64_t number_of_bits);

int make_two_vectors(vector<unsigned char> &dest_one,
                     vector<unsigned char> &dest_two,
                     const vector<unsigned char> &source,
                     vector<unsigned char>::size_type dest_size);

int read_key(vector<unsigned char> &enc_key_vec,
             vector<unsigned char> &auth_key_vec,
             uint_least64_t &exponent,
             uint_least64_t &half_key_length,
             ifstream &key_file);


int read_file(vector<unsigned char> &vec, ifstream &file);

int main(int argc, char *argv[])
{
	/* Sanity check. */
	if (argc != 5) {
		cerr << "Usage: " << argv[0]
		     << " -d|-e <infile> <key> <outfile>\n";
		return EXIT_FAILURE;
	}

	/* Open files. */
	ifstream in_file(argv[2], std::ios_base::binary);
	if (!in_file) {
		cerr << argv[3] << " could not be opened for reading.\n";
		return EXIT_FAILURE;
	}
	ifstream key_file(argv[3], std::ios_base::binary);
	if (!key_file) {
		cerr << argv[3] << " could not be opened for reading.\n";
		return EXIT_FAILURE;
	}

	ofstream out_file(argv[4], std::ios_base::binary);
	if (!out_file) {
		cerr << argv[4] << " could not be opened for writing.\n";
		return EXIT_FAILURE;
	}

	/* Delegate main functionality; check for invalid mode. */
	if (string(argv[1]) == "-e") {
		return encrypt(in_file, key_file, out_file);
	} else if (string(argv[1]) == "-d") {
		return decrypt(in_file, key_file, out_file);
	} else {
		cerr << "Unrecognized operation mode: " << argv[1] << '\n';
		return EXIT_FAILURE;
	}
}

int encrypt(ifstream &plaintext_file, ifstream &key_file,
            ofstream &ciphertext_file)
{
	/* Read in the plaintext. */
	// Prepend 1-byte for unambiguous decryption.
	vector<unsigned char> plaintext_vec(1, 1);
	read_file(plaintext_vec, plaintext_file);
	 // CHECK EMPTY CASE. CHECKED BELOW.


	/* Read in keys. */
	
	
	vector<unsigned char> enc_key_vec;
	vector<unsigned char> auth_key_vec;
	uint_least64_t exponent;
	uint_least64_t half_key_length;
	read_key(enc_key_vec, auth_key_vec, exponent, half_key_length, key_file);


	/* Math: it's good for you. */
	mpz_t p, m, k1, k2;
	mpz_inits(p, m, k1, k2, NULL);
	set_prime(p, exponent); // p is the prime modulus.
	mpz_import(m, plaintext_vec.size(), 1, 1, 1, 0, plaintext_vec.data());
	mpz_import(k1, enc_key_vec.size(), 1, 1, 1, 0, enc_key_vec.data());
	mpz_import(k2, auth_key_vec.size(), 1, 1, 1, 0, auth_key_vec.data());
	if (mpz_cmp(m, p) >= 0 || mpz_cmp_ui(m, 0UL) == 0) {
		cerr << "The message must be smaller than the prime modulus 2 ^ "
		     << exponent << " - 1 and greater than zero.\n";
		mpz_clears(p, m, k1, k2, NULL);
		return EXIT_FAILURE;
	}

	mpz_add(k1, k1, m); // Encryption
	mpz_mod(k1, k1, p); // Keys are transformed into ciphertexts.
	mpz_mul(k2, k2, m); // Authentication
	mpz_mod(k2, k2, p);

	size_t sizeof_phi_k1 = 0;
	unsigned char *phi_k1_data = (unsigned char *)mpz_export(NULL,
	                             &sizeof_phi_k1, 1, 1, 1, 0, k1);
	size_t sizeof_phi_k2 = 0;
	unsigned char *phi_k2_data = (unsigned char *)mpz_export(NULL,
	                             &sizeof_phi_k2, 1, 1, 1, 0, k2);
	mpz_clears(p, m, k1, k2, NULL);
	write_array(ciphertext_file, phi_k1_data, sizeof_phi_k1, half_key_length, false);
	write_array(ciphertext_file, phi_k2_data, sizeof_phi_k2, half_key_length, false);
	free(phi_k1_data);
	free(phi_k2_data);
	return 0;
}
int decrypt(ifstream &ciphertext_file, ifstream &key_file,
            ofstream &plaintext_file)
{
	
	vector<unsigned char> enc_key_vec;
	vector<unsigned char> auth_key_vec;
	uint_least64_t exponent;
	uint_least64_t half_key_length;
	read_key(enc_key_vec, auth_key_vec, exponent, half_key_length, key_file);

	vector<unsigned char> ciphertext_vec;
	read_file(ciphertext_vec, ciphertext_file);
	vector<unsigned char> main_ciphertext;
	vector<unsigned char> mac;
	make_two_vectors(main_ciphertext, mac, ciphertext_vec, half_key_length);



	mpz_t k1, k2, phi_k1, phi_k2, p;
	mpz_inits(k1, k2, phi_k1, phi_k2, p, NULL);
	set_prime(p, exponent);
	mpz_import(k1, enc_key_vec.size(), 1, 1, 1, 0, enc_key_vec.data());
	mpz_import(k2, auth_key_vec.size(), 1, 1, 1, 0, auth_key_vec.data());
	mpz_import(phi_k1, main_ciphertext.size(), 1, 1, 1, 0, main_ciphertext.data());
	mpz_import(phi_k2, mac.size(), 1, 1, 1, 0, mac.data());
	
	mpz_sub(phi_k1, phi_k1, k1);
	mpz_mod(phi_k1, phi_k1, p);
	mpz_mul(k2, phi_k1, k2);
	mpz_mod(k2, k2, p);
	if (mpz_cmp(k2, phi_k2)) {
		cout << "AUTHENTICATION FAILED: Exiting\n";
		return EXIT_FAILURE;
	}

	size_t sizeof_phi_k1 = 0;
	unsigned char *phi_k1_data = (unsigned char *)mpz_export(NULL,
	                             &sizeof_phi_k1, 1, 1, 1, 0, phi_k1);
	mpz_clears(k1, k2, phi_k1, phi_k2, p, NULL);
	write_array(plaintext_file, phi_k1_data, sizeof_phi_k1, half_key_length, true);
	free(phi_k1_data);
	return 0;
}
void set_prime(mpz_t p, uint_least64_t exponent)
/* This function takes an initialized mpz_t and returns with that mpz_t
 * set to a mersenne prime. */
{
	mpz_ui_pow_ui(p, 2UL, exponent);
	mpz_sub_ui(p, p, 1UL);
}

int read_key(vector<unsigned char> &enc_key_vec,
             vector<unsigned char> &auth_key_vec,
             uint_least64_t &exponent,
             uint_least64_t &half_key_length,
             ifstream &key_file)
// Read key into key_vec. Return zero on success. Mask off bits.
{
	vector<unsigned char> key_vec;
	read_file(key_vec, key_file);
	exponent = largest_exponent(key_vec.size());
	half_key_length = exponent / 8 + 1;
	make_two_vectors(enc_key_vec, auth_key_vec, key_vec, half_key_length);
	enc_key_vec.at(0) &= bit_mask(exponent);
	auth_key_vec.at(0) &= bit_mask(exponent);
	return 0;
}

int bit_mask(uint_least64_t number_of_bits)
{
	int result = 0;
	int bits_to_mask = number_of_bits % 8;
	cout << "Bit mask input = " << bits_to_mask << endl;
	for (int i = 0; i < bits_to_mask; ++i) {
		result |= 1 << i;
	}
	cout << "Bit mask output " << result << endl;
	return result;
}

void write_array(ofstream &out_file, const unsigned char *array,
                 size_t array_size, uint_least64_t half_key_length, bool decryption)
{
	if (!decryption) {
		for (size_t i = array_size; i < half_key_length; ++i) {
			out_file.put('\0');
		}
	}
	for (size_t i = decryption ? 1 : 0; i < array_size; ++i) {
		out_file.put(static_cast<char>(array[i]));
	}
}

uint_least64_t largest_exponent(uint_least64_t file_length)
/* Return greatest exponent less than that required to encrypt the vector;
 * returns 0 on failure. */
{
	const vector<uint_least64_t> mersenne_prime_exponents = {
		19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423,
		9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049,
		216091, 756839, 859443, 1257787, 1398269, 2976221, 3021377, 6972593, 13466917,
		20996011, 24036583, 25964951, 30402457, 37156667, 42643801, 43112609,
		57885161
	}; // Source: http://www.mersenne.org/primes/
	uint_least64_t exponent = file_length * 4;
	for (std::int_least64_t i = mersenne_prime_exponents.size() - 1; i >= 0; --i) {
		if (mersenne_prime_exponents[i] <= exponent) {
            cout << "largest exp returns: " << mersenne_prime_exponents[i] << endl;
			return mersenne_prime_exponents[i];
		}
	}
	return 0;
}

ifstream::pos_type get_length(ifstream &file)
/* Note that this function requires a binary file. */
{
	auto current_position = file.tellg();
	file.seekg(0, file.end);
	auto file_length = file.tellg();
	file.seekg(current_position);
	return file_length;
}

int make_two_vectors(vector<unsigned char> &dest_one,
                     vector<unsigned char> &dest_two,
                     const vector<unsigned char> &source,
                     vector<unsigned char>::size_type dest_size)
{
    vector<unsigned char>::size_type i;
    for (i = 0; i < dest_size; ++i) {
        dest_one.push_back(source.at(i));
    }
    for (; i < 2 * dest_size; ++i) {
        dest_two.push_back(source.at(i));
    }
    return 0;
}

int read_file(vector<unsigned char> &vec, ifstream &file)
/* This function appends the contents of file to vec. */
{
    for (char ch; file.get(ch);) {
		vec.push_back(static_cast<unsigned char>(ch));
	}
	return 0;
}
