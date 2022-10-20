// Secure_Hash_Algorithm256.h : Include file for standard system include files,
// or project specific include files.

#include <iostream>
#include <assert.h>
#include <deque>
#include <string>
#pragma once

struct Block {
	std::uint8_t _512BitDataChunks[64] = {};
};

struct MsgBlock {
	std::uint32_t _512BitMsgBlock[64] = {};
};

class SHA_256 {
public:
	SHA_256();
	// Store the bits of the Message
	void StoreMessageInASCII(std::string&);
	// Parse Message into 512 BIT Blocks
	void Create512BitChunks();
	// Create new Chunk when Chunk exceeds 56 Bytes
	Block CreateNew512BitChunk(Block* block, std::deque<std::uint8_t>& endBits, bool addEndBits);
	// Parse Chunks for Message Schedule
	void MessageScheduleFromEachBlock();
	// Compress Each Message Block, Returning that Hashed Value For each block
	void CompressMessageBlock();
	// Takes a string and computes the hash
	std::string Digest(std::string inputStr);
	// Clear all varibales to perform another hash
	void WipeData();

	// ---- Bitwise Operators ----
	std::uint32_t RotateBitsRight(std::uint32_t, std::uint32_t);
	std::uint32_t ShiftBitsLeft(std::uint32_t, std::uint32_t);
	std::uint32_t Choice(std::uint32_t, std::uint32_t, std::uint32_t);
	std::uint32_t Majority(std::uint32_t, std::uint32_t, std::uint32_t);
	std::uint32_t σ_Sigma0(std::uint32_t); // Lower Case Sigma0
	std::uint32_t σ_Sigma1(std::uint32_t); // Lower Case Sigma1
	std::uint32_t Σ_Sigma0(std::uint32_t); // Upper Case Sigma0
	std::uint32_t Σ_Sigma1(std::uint32_t); // Upper Case Sigma1

	// ---- Utilitiy Functions ----
	void decToBinary(std::uint8_t, bool, bool);
	void decToBinary32(std::uint32_t, bool, bool);
	void decToBinary64(std::uint64_t, bool, bool);
	std::deque<std::uint8_t> Bit64To8Bit(std::uint64_t);
	void ConvertBinaryToHex();
	void View(bool, bool, bool, bool, bool, bool);

private:
	std::deque<std::uint8_t> _InputMessage; // Input Message In ASCII
	std::deque<Block> _blocks;
	std::deque<MsgBlock> _msgBlock; // Stores the MessageBlocks
	std::uint32_t _workingVariables[8]; // Stores A, B, C, D, E, F, G, H which is the Hashed Values
	std::uint64_t L; // Length of Message in  Bits
	std::string _HashedStringInHex;
	std::uint32_t m_blockLength; // Keeps track of the length for each block
	std::uint32_t _compressedMessage[8];
	std::uint32_t _hashWorkers[8];
	const std::uint32_t _hashValues[8] { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab , 0x5be0cd19 };
	const std::uint32_t _roundConstants[64] {   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
					 	    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
						    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
						    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
						    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
						    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
						    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
						    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
};
