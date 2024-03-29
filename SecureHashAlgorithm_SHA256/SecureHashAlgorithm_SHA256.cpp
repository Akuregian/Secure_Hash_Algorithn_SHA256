﻿// SecureHashAlgorithm_SHA256.cpp : Defines the entry point for the application.
//

#include "SecureHashAlgorithm_SHA256.h"
#include <bitset>

SHA_256::SHA_256() : L(0), m_blockLength(0) {
	for (int i = 0; i <= 7; i++) {
		_compressedMessage[i] = std::uint32_t(0);
	}

	for (int i = 0; i <= 7; i++) {
		_hashWorkers[i] = _hashValues[i];
	}
}

std::string SHA_256::Digest(std::string inputStr) {
	StoreMessageInASCII(inputStr);
	Create512BitChunks();
	MessageScheduleFromEachBlock();
	CompressMessageBlock();
	ConvertBinaryToHex();
	WipeData();
	return _HashedStringInHex;
}

void SHA_256::StoreMessageInASCII(std::string& inputStr) {
	// Add Input Message
	for (std::size_t i = 0; i <= inputStr.length() - 1; i++) {
		_InputMessage.push_back((unsigned int)inputStr[i]);
	}
	// Add 1 Bit, shifting it over to keep the 512 bits maximum
	std::uint8_t one = std::uint8_t(1);
	one = (one << 7);
	_InputMessage.push_back(one);
	L = (inputStr.length() * 8); // Original Length of Input Message
}

void SHA_256::Create512BitChunks() {
	// Create a New Block
	Block *block = new Block;
	//std::uint8_t block_len = (L/8) >= 56 ? 64 : 56;
	std::deque<std::uint8_t> endBits = Bit64To8Bit(L);

	int counter = 0;
	for (std::size_t i = 0; i <= _InputMessage.size() - 1; i++) {
		//assert(counter % 65 == 0);
		block->_512BitDataChunks[counter++] = _InputMessage[i];

		// ERROR: When String length == 63..
		// Create block of 56 bytes [448 bits] with 64 bit reserve
		if (counter % 64 == 0) {
			// If Counter is greater than 56, We need a new block
			if (counter == 64 && i == _InputMessage.size() - 1) {

				// Creates a new Block
				Block newBlock;
				// new counter
				int counter_1 = 0;
				int overflow = 64 - counter;
				// Add the overflow bytes to a new chunk
				for (int i = 56; i < (56 + overflow); i++) {
					newBlock._512BitDataChunks[counter_1++] = block->_512BitDataChunks[i];
				}

				// Pad new block
				int K = (56 - counter_1);
				for (std::size_t i = 0; i < K; i++) {
					newBlock._512BitDataChunks[counter_1++] = std::uint8_t(0);
				}

				// Add endBits
				for (std::size_t i = 0; i <= 7; i++) {
					newBlock._512BitDataChunks[counter_1++] = endBits[i];
				}

				_blocks.push_back(*block);
				_blocks.push_back(newBlock);
				return;
			}

			// push_back the block
			_blocks.push_back(*block);

			// End of Block, Reset Counter
			block = new Block;
			counter = 0;
		}
		else if (i == _InputMessage.size() - 1) { 
			// If Counter is less than 56, Pad Zeros
			if (counter < 56) {
				// Pad Zeros till 448 bits
				int K = (56 - counter);
				for (std::size_t i = 0; i < K; i++) {
					block->_512BitDataChunks[counter++] = std::uint8_t(0);
				}
			}
			// If Counter is greater than 56, We need a new block
			if (counter > 56) {
				Block newBlock = CreateNew512BitChunk(block, endBits, true);
				_blocks.push_back(*block);
				_blocks.push_back(newBlock);
				return;
			}

			// Add endBits
			for (std::size_t i = 0; i <= 7; i++) {
				block->_512BitDataChunks[counter++] = endBits[i];
			}

			// push_back the block
			_blocks.push_back(*block);
		//	delete block;
		}
	}
}

Block SHA_256::CreateNew512BitChunk(Block* block, std::deque<std::uint8_t>& endBits, bool addEndBits) {

	// Creates a new Block
	Block newBlock;
	// new counter
	int counter_1 = 0;
	// Add the overflow bytes to a new chunk
	for (int i = 56; i < 64; i++) {
		newBlock._512BitDataChunks[counter_1] = block->_512BitDataChunks[i];
	}

	// Pad new block
	int K = (56 - counter_1);
	for (std::size_t i = 0; i < K; i++) {
		newBlock._512BitDataChunks[counter_1++] = std::uint8_t(0);
	}

	if (addEndBits) {
		// Add endBits
		for (std::size_t i = 0; i <= 7; i++) {
			newBlock._512BitDataChunks[counter_1++] = endBits[i];
		}
	}

	return newBlock;
}

void SHA_256::MessageScheduleFromEachBlock() {
	// Take the 64 8-bit Bytes from _DataChunks and Convert them to 16 32-bit words
	MsgBlock* msgBlock;
	int counter = 0;
	// For Each Block....
	for (std::size_t i = 0; i <= _blocks.size() - 1; i++) {
		msgBlock = new MsgBlock;
		// Grab ONLY the first 16 words for each block (16 x 32) = 512 Bits
		for (std::size_t j = 0; j <= 63; j += 4) {
			// Store these 16 words inside a msgBlock using bitwise
			msgBlock->_512BitMsgBlock[counter++] = (((_blocks[i]._512BitDataChunks[j] & 0xFF) << 24) | ((_blocks[i]._512BitDataChunks[j+1] & 0xFF) << 16) 
				| ((_blocks[i]._512BitDataChunks[j+2] & 0xFF) << 8) | (_blocks[i]._512BitDataChunks[j+3]));
		}
		// Process the next 48 words to fill the msgBlock
		for (std::size_t k = counter; k <= 63; k++) {
			// Generate the 48 Words : w[i] := s1[k-2] + w[k-7] + s0[k-15] + w[k-16] 
			msgBlock->_512BitMsgBlock[k] = σ_Sigma1(msgBlock->_512BitMsgBlock[k - 2]) + msgBlock->_512BitMsgBlock[k - 7] + 
										   σ_Sigma0(msgBlock->_512BitMsgBlock[k - 15]) + msgBlock->_512BitMsgBlock[k - 16];
		}
		// now push the block back and process the next block
		_msgBlock.push_back(*msgBlock);
		counter = 0;
	}
	delete msgBlock;
}

void SHA_256::CompressMessageBlock() {

	// For Every Block -- WORKS for a single block. ERROR occurs when theres more than one block.............. dufFUK>?
	for (std::size_t i = 0; i <= _msgBlock.size() - 1; i++) {

		// Initialize the _workingVariables, if second chunk then set with the values from the previous chunk
		for (std::size_t k = 0; k <= 7; k++) {
			_workingVariables[k] = _hashWorkers[k];
		}

		for (std::size_t j = 0; j <= 63; j++) { // --> repeats for every word in message scheudle
			// Run the Compression Algorithm onto _workingVariables
			// create 2 Temporary Storage Words:
			// std::uint32_t TMP1 = UpperSigma1(e) + choice(e,f,g) + h + roundCountant[i] + msgBlock[i]
			std::uint32_t tempBit1 = Σ_Sigma1(_workingVariables[4]) + Choice(_workingVariables[4], _workingVariables[5], _workingVariables[6])
											  + _workingVariables[7] + _roundConstants[j] + _msgBlock[i]._512BitMsgBlock[j];
			// std::uint32_t TMP2 = UpperSigma0(a) + Majority(a,b,c)
			std::uint32_t tempBit2 = (Σ_Sigma0(_workingVariables[0]) + Majority(_workingVariables[0], _workingVariables[1], _workingVariables[2]));
			// Move all state variables down one, losing the 7th byte ('H'), but opening up the 1st byte ('A')
			// add to (TMP1 + TMP2) to _workingVariables[0] otherwise known as the ('A') working variable 
			// Add TMP1 to _workingVariables[4] otherwise knwon as ('E') working variable
			/*H*/	_workingVariables[7] = _workingVariables[6];
			/*G*/	_workingVariables[6] = _workingVariables[5];
			/*F*/	_workingVariables[5] = _workingVariables[4];
			/*E*/	_workingVariables[4] = ( _workingVariables[3] + tempBit1 );
			/*D*/	_workingVariables[3] = _workingVariables[2];
			/*C*/	_workingVariables[2] = _workingVariables[1];
			/*B*/	_workingVariables[1] = _workingVariables[0];
			/*A*/	_workingVariables[0] = ( tempBit1 + tempBit2 );
		}

		// Take the Inital hash values and add on the new hashed values
		for (std::size_t m = 0; m <= 7; m++) {
			_hashWorkers[m] += _workingVariables[m] & 0xFFFFFFFF;
		}
	}
	// Store the compressed Message (Testing purposes)
	for (std::size_t i = 0; i <= 7; i++) {
		_compressedMessage[i] = _hashWorkers[i];
	}
}

void SHA_256::WipeData() {
	_InputMessage.clear();
	_blocks.clear();
	_msgBlock.clear();
	for (int i = 0; i <= 7; i++) {
		_hashWorkers[i] = _hashValues[i];
	}
	for (int i = 0; i <= 7; i++) {
		_compressedMessage[i] = 0;
	}
	for (int i = 0; i <= 7; i++) {
		_workingVariables[i] = 0;
	}
}

// ----------------------------- Bitwise Operators -------------------------------
// Shift Bits over to the Right X amount of times
std::uint32_t SHA_256::RotateBitsRight(std::uint32_t word, std::uint32_t shift) {
	return (word >> shift) | (word << (32 - shift));
}
// Shift Bits over to the Left X amoutn of times
std::uint32_t SHA_256::ShiftBitsLeft(std::uint32_t word, std::uint32_t shift) {
	return (word >> shift) | (word << (shift));
}
// Choice uses the First Word to decide which other word to choose. if decidingWord == 1, choiceA, else choiceB
std::uint32_t SHA_256::Choice(std::uint32_t decidingWord, std::uint32_t choiceA, std::uint32_t choiceB) {
	return (decidingWord & choiceA) ^ (~decidingWord & choiceB);
}
// Majority takes the 'majority' bit of the 3 words. Either a 1 or 0 depending on which one is greater when adding them 
std::uint32_t SHA_256::Majority(std::uint32_t wordA, std::uint32_t wordB, std::uint32_t wordC) {
	return (wordA & (wordB | wordC)) | (wordB & wordC);
}
// LowerCase sigma0 : Shifts bits of word X amount and XOR them together
std::uint32_t SHA_256::σ_Sigma0(std::uint32_t word) {
	return RotateBitsRight(word, 7) ^ RotateBitsRight(word, 18) ^ (word >> 3);
}
// LowerCase sigma1 : Shift bits of word X amount and XOR them together
std::uint32_t SHA_256::σ_Sigma1(std::uint32_t word) {
	return RotateBitsRight(word, 17) ^ RotateBitsRight(word, 19) ^ (word >> 10);
}
// UpperCase Sigma0 : Shifts bits of word X amount and XOR them together
std::uint32_t SHA_256::Σ_Sigma0(std::uint32_t word) {
	return RotateBitsRight(word, 2) ^ RotateBitsRight(word, 13) ^ RotateBitsRight(word, 22);
}
// UpperCase Sigma1 : Shift bits of word X amount and XOR them together
std::uint32_t SHA_256::Σ_Sigma1(std::uint32_t word) {
	return RotateBitsRight(word, 6) ^ RotateBitsRight(word, 11) ^ RotateBitsRight(word, 25);
}

// ------------------------------ Utility Functions ------------------------------
void SHA_256::decToBinary(std::uint8_t n, bool SigBits, bool AllBits) {
	if (AllBits) {
		if (n == 0) {
			std::cout << "0";
			return;
		}
		// array to store binary number
		int binaryNum[32];
		// counter for binary array
		int i = 0;
		while (n > 0) {
			// storing remainder in binary array
			binaryNum[i] = n % 2;
			n = n / 2;
			i++;
		}
		// printing binary array in reverse order
		for (int j = i - 1; j >= 0; j--) {
			std::cout << binaryNum[j];
		}
	}
	else if (SigBits) {

		// Size of an integer is 8 bits
		for (int i = 7; i >= 0; i--) {
			int k = n >> i;
			if (k & 1)
				std::cout << "1";
			else
				std::cout << "0";
		}
	//	std::cout << " ";
	}
}

void SHA_256::decToBinary32(std::uint32_t n, bool SigBits, bool AllBits) {
	if (AllBits) {
		if (n == 0) {
			std::cout << "0";
			return;
		}
		// array to store binary number
		int binaryNum[32];
		// counter for binary array
		int i = 0;
		while (n > 0) {
			// storing remainder in binary array
			binaryNum[i] = n % 2;
			n = n / 2;
			i++;
		}
		// printing binary array in reverse order
		for (int j = i - 1; j >= 0; j--) {
			std::cout << binaryNum[j];
		}
	}
	else if (SigBits) {
		// Size of an integer is assumed to be 32 bits
		for (int i = 31; i >= 0; i--) {
			int k = n >> i;
			if (k & 1)
				std::cout << "1";
			else
				std::cout << "0";
		}
	}
}

void SHA_256::decToBinary64(std::uint64_t n, bool SigBits, bool AllBits) {
	if (AllBits) {
		if (n == 0) {
			std::cout << "0";
			return;
		}
		// array to store binary number
		int binaryNum[64];
		// counter for binary array
		int i = 0;
		while (n > 0) {
			// storing remainder in binary array
			binaryNum[i] = n % 2;
			n = n / 2;
			i++;
		}
		// printing binary array in reverse order
		for (int j = i - 1; j >= 0; j--) {
			std::cout << binaryNum[j];
		}
	}
	else if (SigBits) {
		// Size of an integer is assumed to be 32 bits
		for (int i = 63; i >= 0; i--) {
			int k = n >> i;
			if (k & 1)
				std::cout << "1";
			else
				std::cout << "0";
		}
	}
}

void SHA_256::View(bool bytes, bool message, bool chunk, bool messageSchedule, bool compressedMessage, bool hashResult) {

	if (message) {
		std::cout << "----------------- Printing Message -----------------\n";
		std::cout << "Input Message[" << _InputMessage.size() << "]: [";
		for (std::size_t i = 0; i <= _InputMessage.size() - 2; i++) { 
			std::cout << _InputMessage[i] << ", ";
		}
		std::cout << "]\n" << std::endl;
	}
	if (bytes) {
		//--------- Displays Bytes In Integer Form ------
		std::cout << "----------------- Printing Bits -----------------\n";
		std::cout << "Bytes[" << _InputMessage.size() << "]: [";
		for (auto i : _InputMessage) {
			std::cout << (int)i << ", ";
		}
		std::cout << "]" << " - Size[" << _InputMessage.size() * 8 << "] in Bits" << std::endl << std::endl;

		// --------- Display Bytes in Binary -----------
		std::cout << "Message[" << _InputMessage.size()*8 <<"] in bits:";
		for (std::size_t i = 0; i < _InputMessage.size() ; i++) {
			decToBinary(_InputMessage[i], true, false);
		}
		std::cout << std::endl;
	}
	if (chunk) {
		std::cout << "----------------- Bit Chunks -----------------\n";
		std::cout << std::endl << "BlockData: (OriginalMessageInBits = " <<  L << ")"<< std::endl;
		for (std::size_t i = 0; i <= _blocks.size() - 1; i++) {
			std::cout << "\n\n Block[" << i << "]" << std::endl;
			for (std::size_t j = 0; j < 64; j++) {
				decToBinary(_blocks[i]._512BitDataChunks[j], true, false);
			}
		}
	}

	if (messageSchedule) {
		std::cout << "\n----------------- Message Schedule -----------------\n";
		std::cout << "\n\nMessageSchedule[" << _msgBlock.size() << "] -> [ ";
		for (std::size_t i = 0; i <= _msgBlock.size() - 1; i++) {
			for (std::size_t j = 0; j < 64; j++) {
				std::cout << "\nM[" << i << "][" << j << "] : ";
				decToBinary32(_msgBlock[i]._512BitMsgBlock[j], true, false);
			}
			std::cout << std::endl;
			std::cout << "-----------------------------------------------" << std::endl;
		}
		std::cout << " ]\n" << std::endl;
	}

	if (compressedMessage) {
		std::cout << "\n----------------- Compress Message -----------------\n";
		std::cout << "\n\nThis Is the Final Message Block, Which can be converted to HEXADECIMAL.\n\n";
		for (auto i : _compressedMessage) {
			decToBinary32(i, true, false); std::cout << std::endl;
		}
		std::cout << std::endl;
	}

	if (hashResult) {
		std::cout << "----------------- Final Hash -----------------\n";
		std::cout << "Final Hash: " << _HashedStringInHex << std::endl;
	}
}

std::deque<std::uint8_t> SHA_256::Bit64To8Bit(std::uint64_t bigBits) {
	std::deque<std::uint8_t> smallBits;
	for (std::size_t i = 0; i <= 7; i++) {
		// PushBack the Last 8 Bits of the 64 Bit integer
		std::uint8_t tmp = (bigBits & 0xFF);
		smallBits.push_back(tmp);
		// Shift Bits to right 8 spaces
		bigBits = bigBits >> 8;
	}
	std::deque<std::uint8_t> orderedSmallBits;
	for (int i = smallBits.size() - 1; i >= 0; i--) {
		orderedSmallBits.push_back(smallBits[i]);
	}
	return orderedSmallBits;
}

void SHA_256::ConvertBinaryToHex() {
	// Take the _hashedValues and convert
	std::string hexString = "";

	// char array to store hexadecimal number
	std::deque<char> hexaDeciNum;

	// int k = 0;
	for (std::size_t i = 0; i <= 7; i++) {

		// counter for hexadecimal number array
		while (_hashWorkers[i] != 0) {
			// temporary variable to store remainder
			int temp = 0;

			// storing remainder in temp variable.
			temp = _hashWorkers[i] % 16;

			// check if temp < 10
			if (temp < 10) {
				hexaDeciNum.push_back(temp + 48);
				//k++;
			}
			else {
				hexaDeciNum.push_back(temp + 55);
				//k++;
			}

			_hashWorkers[i] = _hashWorkers[i] / 16;
		}

		// Ensure 8 values are being placed into the hexString variable
		while (hexaDeciNum.size() < 8) {
			hexaDeciNum.push_back('0');
		}

		for (int j = hexaDeciNum.size() - 1; j >= 0; j--){
			hexString += hexaDeciNum[j];
		}
		hexaDeciNum.clear();

	}
	_HashedStringInHex = hexString;
}
