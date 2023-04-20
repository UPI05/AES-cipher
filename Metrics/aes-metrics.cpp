#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/xtrcrypt.h>

#include <iostream>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <string>

using namespace CryptoPP;
using namespace std;
using namespace std::chrono;

int mode, randomOption = 1, encdecOption, inputOption, repeatTimes;
string filename, plain, cipher, cipher_hex, recovered, key_hex, iv_hex, key, iv;

int main(int argc, char* argv[]) {
	cout << "======== Buoc 1: Chon mode =========" << endl;
	cout << "1. ECB" << endl;
	cout << "2. CBC" << endl;
	cout << "3. OFB" << endl;
	cout << "4. CFB" << endl;
	cout << "5. CTR" << endl;
	cout << "6. XTS" << endl;
	cout << "7. CCM" << endl;
	cout << "Nhap stt 1-7 tu  de chon mode: ";
	cin >> mode;

	while (!(mode >= 1 && mode <= 7)) {
		cout << "STT mode khong hop le, vui long nhap lai: ";
		cin >> mode;
	}

	cout << "======== Buoc 2: Nhap input, key va IV ========" << endl;
	
	cout << "Nhap 0 de ma hoa, 1 de giai ma: ";

	cin >> encdecOption;

	cout << "Nhap 0 de doc tu man hinh, 1 de doc tu file: ";

	cin >> inputOption;

	if (encdecOption == 0) {

		cout << "Nhap 0 de sinh key va iv ngau nhien, 1 neu khong muon: ";

		cin >> randomOption;
	}
	cout << "Nhap so lan lap: ";
	cin >> repeatTimes;

	if (inputOption == 0) {	
		if (encdecOption == 0) {
			cout << "Nhap plaintext: ";
			cin.ignore();
			getline(cin, plain);

		} else {
			cout << "Nhap cipher (hexadecimal): ";
			cin >> cipher_hex;
			// Convert cipher from hex to binary 
			CryptoPP::StringSource(cipher_hex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(cipher)));
		}
		if (randomOption == 1) {
			cout << "Nhap key (dang hexadecimal): ";
			cin >> key_hex;
			cout << "Nhap IV (neu co) (dang hexadecimal): ";
			cin >> iv_hex;
		}
	} else {
		cout << "Nhap file can doc: ";
		cin >> filename;
		ifstream file(filename);
		if (encdecOption == 0) {
			getline(file, plain);
		} else {
			getline(file, cipher_hex);
			// Convert cipher from hex to binary 
			CryptoPP::StringSource(cipher_hex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(cipher)));
		}
		if (randomOption == 1) {
			getline(file, key_hex);
			getline(file, iv_hex);
		}
		file.close();		
	}

	// Convert key and iv from hex to binary 
	CryptoPP::StringSource(key_hex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(key)));
	CryptoPP::StringSource(iv_hex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(iv)));


	// Generate key and iv
	CryptoPP::byte bkey[AES::DEFAULT_KEYLENGTH], biv[AES::BLOCKSIZE];
    	AutoSeededRandomPool prng;
	if (randomOption == 0) {
		 // Generate a random key and IV
    		prng.GenerateBlock(bkey, sizeof(bkey));
    		prng.GenerateBlock(biv, sizeof(biv));
	}


	cout << "\n=========== Buoc 3: Encrypt hoac decrypt ==========\n";

	// Print key and iv if we generate those randomly
	if (randomOption == 0) {
		// Convert key, iv from byte bin to hex
		CryptoPP::StringSource(bkey, sizeof(bkey), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(key_hex)));
		CryptoPP::StringSource(biv, sizeof(bkey), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(iv_hex)));
		// Convert key, iv from hex to bin
		CryptoPP::StringSource(key_hex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(key)));
		CryptoPP::StringSource(iv_hex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(iv)));
		cout << "Key: " <<  key_hex << endl;
		if (mode != 1) cout << "IV: " << iv_hex << endl;
	}

	cout << plain << endl;


	auto start = high_resolution_clock::now();
	for (int i = 1; i <= repeatTimes; i++) {
		//
		if (mode == 1) {
			// MODE ECB
			if (!encdecOption) {
				cipher = "";
				// Create the AES encryption object
		    		CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption aes;
		    		aes.SetKey((const CryptoPP::byte*)key.data(), key.size());
		    		// Encrypt the plaintext using AES-ECB
		    		CryptoPP::StringSource(plain, true,
					new CryptoPP::StreamTransformationFilter(aes,
			    			new CryptoPP::StringSink(cipher)
					)
		    		);
		    		// Print the ciphertext in hexadecimal format
				if (i == repeatTimes) {
		    		std::cout << "Ciphertext: ";
		    		CryptoPP::StringSource ss1(cipher, true,
					new CryptoPP::HexEncoder(
			    			new CryptoPP::FileSink(std::cout)
					)
		    		);
				}
			} else {
				plain = "";
				// Create the AES decryption object
				CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption aes;
		    		aes.SetKey((const CryptoPP::byte*)key.data(), key.size());

				// Decrypt ciphertext and print out
	 			CryptoPP::StringSource(cipher, true, new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::StringSink(plain)));

				if (i == repeatTimes) {
				cout << "Plain text: " << plain;
				}
			}


		} else if (mode == 2) {
			// MODE CBC
			if (!encdecOption) {
				cipher = "";
				// Create the AES encryption object
		    		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
		    		// Encrypt the plaintext using AES-CBC
		    		CryptoPP::StringSource(plain, true,
					new CryptoPP::StreamTransformationFilter(aes,
			    			new CryptoPP::StringSink(cipher)
					)
		    		);
		    		// Print the ciphertext in hexadecimal format
				if (i == repeatTimes) {
		    		std::cout << "Ciphertext: ";
		    		CryptoPP::StringSource ss1(cipher, true,
					new CryptoPP::HexEncoder(
			    			new CryptoPP::FileSink(std::cout)
					)
		    		);
				}
			} else {
				plain = "";
				// Create the AES decryption object
				CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());

				// Decrypt ciphertext and print out
	 			CryptoPP::StringSource(cipher, true, new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::StringSink(plain)));

				if (i == repeatTimes) {
				cout << "Plain text: " << plain;
				}
			}

		} else if (mode == 3) {
			// MODE OFB
			if (!encdecOption) {
				cipher = "";
				// Create the AES encryption object
		    		CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
		    		// Encrypt the plaintext using AES-OFB
		    		CryptoPP::StringSource(plain, true,
					new CryptoPP::StreamTransformationFilter(aes,
			    			new CryptoPP::StringSink(cipher)
					)
		    		);
		    		// Print the ciphertext in hexadecimal format
				if (i == repeatTimes) {
		    		std::cout << "Ciphertext: ";
		    		CryptoPP::StringSource ss1(cipher, true,
					new CryptoPP::HexEncoder(
			    			new CryptoPP::FileSink(std::cout)
					)
		    		);
				}
			} else {
				plain = "";
				// Create the AES decryption object
				CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());

				// Decrypt ciphertext and print out
	 			CryptoPP::StringSource(cipher, true, new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::StringSink(plain)));
				if (i == repeatTimes) {
				cout << "Plain text: " << plain;
				}
			}

		} else if (mode == 4) {
			// MODE CFB
			if (!encdecOption) {
				cipher = "";
				// Create the AES encryption object
		    		CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
		    		// Encrypt the plaintext using AES-CFB
		    		CryptoPP::StringSource(plain, true,
					new CryptoPP::StreamTransformationFilter(aes,
			    			new CryptoPP::StringSink(cipher)
					)
		    		);
		    		// Print the ciphertext in hexadecimal format
				if (i == repeatTimes) {
		    		std::cout << "Ciphertext: ";
		    		CryptoPP::StringSource ss1(cipher, true,
					new CryptoPP::HexEncoder(
			    			new CryptoPP::FileSink(std::cout)
					)
		    		);
				}
			} else {
				plain = "";
				// Create the AES decryption object
				CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());

				// Decrypt ciphertext and print out
	 			CryptoPP::StringSource(cipher, true, new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::StringSink(plain)));

				if (i == repeatTimes) {
				cout << "Plain text: " << plain;
				}
			}

		} else if (mode == 5) {
			// MODE CTR
			if (!encdecOption) {
				cipher = "";
				// Create the AES encryption object
		    		CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
		    		// Encrypt the plaintext using AES-CTR
		    		CryptoPP::StringSource(plain, true,
					new CryptoPP::StreamTransformationFilter(aes,
			    			new CryptoPP::StringSink(cipher)
					)
		    		);
		    		// Print the ciphertext in hexadecimal format
				//
				if (i == repeatTimes) {
		    		std::cout << "Ciphertext: ";
		    		CryptoPP::StringSource ss1(cipher, true,
					new CryptoPP::HexEncoder(
			    			new CryptoPP::FileSink(std::cout)
					)
		    		);
				}
			} else {
				plain = "";
				// Create the AES decryption object
				CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());

				// Decrypt ciphertext and print out
	 			CryptoPP::StringSource(cipher, true, new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::StringSink(plain)));
				if (i == repeatTimes) {
				cout << "Plain text: " << plain;
				}

			}

		} else if (mode == 6) {
			// MODE XTS
			if (!encdecOption) {
				cipher = "";
				// Create the AES encryption object
		    		CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
		    		// Encrypt the plaintext using AES-XTS
		    		CryptoPP::StringSource(plain, true,
					new CryptoPP::StreamTransformationFilter(aes,
			    			new CryptoPP::StringSink(cipher)
					)
		    		);
		    		// Print the ciphertext in hexadecimal format
		    		std::cout << "Ciphertext: ";
		    		CryptoPP::StringSource ss1(cipher, true,
					new CryptoPP::HexEncoder(
			    			new CryptoPP::FileSink(std::cout)
					)
		    		);
			} else {
				plain = "";
				// Create the AES decryption object
				CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());

				// Decrypt ciphertext and print out
	 			CryptoPP::StringSource(cipher, true, new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::StringSink(plain)));
				cout << "Plain text: " << plain;
			}

		} else if (mode == 7) {
			// MODE CCM
			if (!encdecOption) {
				cipher = "";
				// Create the AES encryption object
		    		CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
		    		// Encrypt the plaintext using AES-CCM
		    		CryptoPP::StringSource(plain, true,
					new CryptoPP::StreamTransformationFilter(aes,
			    			new CryptoPP::StringSink(cipher)
					)
		    		);
		    		// Print the ciphertext in hexadecimal format
		    		std::cout << "Ciphertext: ";
		    		CryptoPP::StringSource ss1(cipher, true,
					new CryptoPP::HexEncoder(
			    			new CryptoPP::FileSink(std::cout)
					)
		    		);
			} else {
				plain = "";
				// Create the AES decryption object
				CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption aes;
		    		aes.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());

				// Decrypt ciphertext and print out
	 			CryptoPP::StringSource(cipher, true, new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::StringSink(plain)));
				cout << "Plain text: " << plain;
			}

		}
		cout << endl << endl;
	}
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop - start);
 
    	cout << "\nTime taken: " << duration.count() << " microseconds" << endl;
    	cout << "Avarage time: " << duration.count() / (double) repeatTimes << " microseconds" << endl;

	return 0;
}
