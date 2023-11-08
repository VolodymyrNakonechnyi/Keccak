#include <iostream>
#include <cmath>
#include <algorithm>
#include <cstdint>
#include <cstring>
#define MIN(a,b)((a > b) ? b : a);

const int KeccakRhoOffsets[24] = 
{ 1,  3,   6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44 };

void KeccakTheta(uint8_t* state) {
    uint8_t C[5], D[5];

    for (int x = 0; x < 5; ++x) {
        C[x] = state[x] ^ state[5 + x] ^ state[10 + x] ^ state[15 + x] ^ state[20 + x];
    }

    for (int x = 0; x < 5; ++x) {
        D[x] = C[(x + 4) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 7));
    }

    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            state[y * 5 + x] ^= D[x];
        }
    }
}

void KeccakRho(uint8_t* state) {
    for (int i = 0; i < 24; ++i) {
        int x = 1, y = 0;
        int offset = KeccakRhoOffsets[i];
        uint8_t current = state[y * 5 + x];

        for (int j = 0; j < offset; ++j) {
            int tempX = x;
            x = y;
            y = (2 * tempX + 3 * y) % 5;

            uint8_t temp = current;
            current = state[y * 5 + x];
            state[y * 5 + x] = temp;
        }
    }
}

void KeccakPi(uint8_t* state) {
    uint8_t tempState[25];
    std::memcpy(tempState, state, 25 * sizeof(uint8_t));

    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            state[y * 5 + (2 * x + 3 * y) % 5] = tempState[x * 5 + y];
        }
    }
}


void KeccakChi(uint8_t* state) {
    uint8_t tempState[25];
    std::memcpy(tempState, state, 25 * sizeof(uint8_t));

    // Apply Chi step
    for (int y = 0; y < 5; ++y) {
        for (int x = 0; x < 5; ++x) {
            state[y * 5 + x] = tempState[y * 5 + x] ^ ((tempState[y * 5 + ((x + 1) % 5)] ^ 1) & tempState[y * 5 + ((x + 2) % 5)]);
        }
    }
}


void KeccakIota(uint8_t* state, int round) {
    static const uint64_t roundConstants[24] = {1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
   0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
   0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
   0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
   0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
   0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

    state[0] ^= roundConstants[round];
}

void KeccakF1600_StatePermute(uint8_t* state) {
    for (int round = 0; round < 24; ++round) {
        KeccakTheta(state);
        KeccakRho(state);
        KeccakPi(state);
        KeccakChi(state);
        KeccakIota(state, round);
    }
}

void keccak(int rate, int capacity, uint8_t input [], unsigned int inputByteLen, unsigned char delimitedSuffix, unsigned char* output, unsigned long long int outputByteLen) {
    
    uint8_t state[200] = {0};
    unsigned int rateInBytes = rate / 8;
    unsigned int blockSize = 0;
    unsigned int i;

    while (inputByteLen > 0) {
        blockSize = MIN(inputByteLen, rateInBytes);
        for (i = 0; i < blockSize; i++)
            state[i] ^= input[i];
        input += blockSize;
        inputByteLen -= blockSize;

        if (blockSize == rateInBytes) {
            KeccakF1600_StatePermute(state);
            blockSize = 0;
        }
    }



    state[blockSize] ^= delimitedSuffix;
    if (((delimitedSuffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
        KeccakF1600_StatePermute(state);
    state[rateInBytes - 1] ^= 0x80;
    KeccakF1600_StatePermute(state);

    while (outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        memcpy(output, state, blockSize);
        output += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0)
            KeccakF1600_StatePermute(state);
    }
}   

int main()
{
    const char* input_string = "abc";
    unsigned char output[32];

    uint8_t input[2] = {61, 62};

    keccak(1088, 512, input, 2, 0x06, output, 64);

    std::cout << ("SHA-3 256-bit Hash:");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", output[i]);
    }
    printf("\n");

    return 0;
}

