#include <iostream>
#include <cstring>
#include <chrono>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char* input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char* output, unsigned long long int outputByteLen);

/**
  *  Function to compute SHAKE128 on the input message with any output length.
  */
void FIPS202_SHAKE128(const unsigned char* input, unsigned int inputByteLen, unsigned char* output, int outputByteLen)
{
    Keccak(1344, 256, input, inputByteLen, 0x1F, output, outputByteLen);
}

/**
  *  Function to compute SHAKE256 on the input message with any output length.
  */
void FIPS202_SHAKE256(const unsigned char* input, unsigned int inputByteLen, unsigned char* output, int outputByteLen)
{
    Keccak(1088, 512, input, inputByteLen, 0x1F, output, outputByteLen);
}

/**
  *  Function to compute SHA3-224 on the input message. The output length is fixed to 28 bytes.
  */
void FIPS202_SHA3_224(const unsigned char* input, unsigned int inputByteLen, unsigned char* output)
{
    Keccak(1152, 448, input, inputByteLen, 0x06, output, 28);
}

/**
  *  Function to compute SHA3-256 on the input message. The output length is fixed to 32 bytes.
  */
void FIPS202_SHA3_256(const unsigned char* input, unsigned int inputByteLen, unsigned char* output)
{
    Keccak(1088, 512, input, inputByteLen, 0x06, output, 32);
}

/**
  *  Function to compute SHA3-384 on the input message. The output length is fixed to 48 bytes.
  */
void FIPS202_SHA3_384(const unsigned char* input, unsigned int inputByteLen, unsigned char* output)
{
    Keccak(832, 768, input, inputByteLen, 0x06, output, 48);
}

/**
  *  Function to compute SHA3-512 on the input message. The output length is fixed to 64 bytes.
  */
void FIPS202_SHA3_512(const unsigned char* input, unsigned int inputByteLen, unsigned char* output)
{
    Keccak(576, 1024, input, inputByteLen, 0x06, output, 64);
}

/*
================================================================
Technicalities
================================================================
*/

#include <stdint.h>

typedef uint64_t tKeccakLane;

#ifndef LITTLE_ENDIAN
/** Function to load a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
static uint64_t load64(const uint8_t* x)
{
    int i;
    uint64_t u = 0;

    for (i = 7; i >= 0; --i) {
        u <<= 8;
        u |= x[i];
    }
    return u;
}

/** Function to store a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
static void store64(uint8_t* x, uint64_t u)
{
    unsigned int i;

    for (i = 0; i < 8; ++i) {
        x[i] = u;
        u >>= 8;
    }
}

/** Function to XOR into a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
static void xor64(uint8_t* x, uint64_t u)
{
    unsigned int i;

    for (i = 0; i < 8; ++i) {
        x[i] ^= u;
        u >>= 8;
    }
}
#endif

/*
================================================================
A readable and compact implementation of the Keccak-f[1600] permutation.
================================================================
*/

#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#define i(x, y) ((x)+5*(y))

#ifdef LITTLE_ENDIAN
#define readLane(x, y)          (((tKeccakLane*)state)[i(x, y)])
#define writeLane(x, y, lane)   (((tKeccakLane*)state)[i(x, y)]) = (lane)
#define XORLane(x, y, lane)     (((tKeccakLane*)state)[i(x, y)]) ^= (lane)
#else
#define readLane(x, y)          load64((uint8_t*)state+sizeof(tKeccakLane)*i(x, y))
#define writeLane(x, y, lane)   store64((uint8_t*)state+sizeof(tKeccakLane)*i(x, y), lane)
#define XORLane(x, y, lane)     xor64((uint8_t*)state+sizeof(tKeccakLane)*i(x, y), lane)
#endif

/**
  * Function that computes the linear feedback shift register (LFSR) used to
  * define the round constants (see [Keccak Reference, Section 1.2]).
  */
int LFSR86540(uint8_t* LFSR)
{
    int result = ((*LFSR) & 0x01) != 0;
    if (((*LFSR) & 0x80) != 0)
        /* Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
        (*LFSR) = ((*LFSR) << 1) ^ 0x71;
    else
        (*LFSR) <<= 1;
    return result;
}

/**
 * Function that computes the Keccak-f[1600] permutation on the given state.
 */
void KeccakF1600_StatePermute(void* state)
{
    unsigned int round, x, y, j, t;
    uint8_t LFSRstate = 0x01;

    for (round = 0; round < 24; round++) {
        {   /* === θ step (see [Keccak Reference, Section 2.3.2]) === */
            tKeccakLane C[5], D;

            /* Compute the parity of the columns */
            for (x = 0; x < 5; x++)
                C[x] = readLane(x, 0) ^ readLane(x, 1) ^ readLane(x, 2) ^ readLane(x, 3) ^ readLane(x, 4);
            for (x = 0; x < 5; x++) {
                /* Compute the θ effect for a given column */
                D = C[(x + 4) % 5] ^ ROL64(C[(x + 1) % 5], 1);
                /* Add the θ effect to the whole column */
                for (y = 0; y < 5; y++)
                    XORLane(x, y, D);
            }
        }

        {   /* === ρ and π steps (see [Keccak Reference, Sections 2.3.3 and 2.3.4]) === */
            tKeccakLane current, temp;
            /* Start at coordinates (1 0) */
            x = 1; y = 0;
            current = readLane(x, y);
            /* Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23 */
            for (t = 0; t < 24; t++) {
                /* Compute the rotation constant r = (t+1)(t+2)/2 */
                unsigned int r = ((t + 1) * (t + 2) / 2) % 64;
                /* Compute ((0 1)(2 3)) * (x y) */
                unsigned int Y = (2 * x + 3 * y) % 5; x = y; y = Y;
                /* Swap current and state(x,y), and rotate */
                temp = readLane(x, y);
                writeLane(x, y, ROL64(current, r));
                current = temp;
            }
        }

        {   /* === χ step (see [Keccak Reference, Section 2.3.1]) === */
            tKeccakLane temp[5];
            for (y = 0; y < 5; y++) {
                /* Take a copy of the plane */
                for (x = 0; x < 5; x++)
                    temp[x] = readLane(x, y);
                /* Compute χ on the plane */
                for (x = 0; x < 5; x++)
                    writeLane(x, y, temp[x] ^ ((~temp[(x + 1) % 5]) & temp[(x + 2) % 5]));
            }
        }

        {   /* === ι step (see [Keccak Reference, Section 2.3.5]) === */
            for (j = 0; j < 7; j++) {
                unsigned int bitPosition = (1 << j) - 1; /* 2^j-1 */
                if (LFSR86540(&LFSRstate))
                    XORLane(0, 0, (tKeccakLane)1 << bitPosition);
            }
        }
    }
}

/*
================================================================
A readable and compact implementation of the Keccak sponge functions
that use the Keccak-f[1600] permutation.
================================================================
*/

#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char* input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char* output, unsigned long long int outputByteLen)
{
    uint8_t state[200];
    unsigned int rateInBytes = rate / 8;
    unsigned int blockSize = 0;
    unsigned int i;

    if (((rate + capacity) != 1600) || ((rate % 8) != 0))
        return;

    /* === Initialize the state === */
    memset(state, 0, sizeof(state));

    /* === Absorb all the input blocks === */
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

    /* === Do the padding and switch to the squeezing phase === */
    /* Absorb the last few bits and add the first bit of padding (which coincides with the delimiter in delimitedSuffix) */
    state[blockSize] ^= delimitedSuffix;
    /* If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
    if (((delimitedSuffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
        KeccakF1600_StatePermute(state);
    /* Add the second bit of padding */
    state[rateInBytes - 1] ^= 0x80;
    /* Switch to the squeezing phase */
    KeccakF1600_StatePermute(state);

    /* === Squeeze out all the output blocks === */
    while (outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        memcpy(output, state, blockSize);
        output += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0)
            KeccakF1600_StatePermute(state);
    }
}


class KeccakC {
private:
    const uint64_t RC[24] =
    {
      0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
      0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
      0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
      0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
      0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
      0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
      0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };

    uint64_t load64(const uint8_t* x)
    {
        int i;
        uint64_t u = 0;

        for (i = 7; i >= 0; --i) {
            u <<= 8;
            u |= x[i];
        }
        return u;
    }

    void xor64(uint8_t* x, uint64_t u, int index)
    {
        for (uint32_t i = index; i < index + 8; ++i) {
            x[i] ^= u;
            u >>= 8;
        }
    }

    void store64(uint8_t* x, uint64_t u, int index)
    {

        for (uint32_t i = index; i < index + 8; ++i) {
            x[i] = u;
            u >>= 8;
        }
    }

    uint64_t laneRead(int x, int y, uint8_t* state) {
        uint8_t result[8] = { 0 };

        for (int i = 0; i < 8; i++) {
            result[i] ^= state[i + (x * 8) + (y * 40)];
        }


        return load64(result);
    }

    void laneWrite(int x, int y, uint8_t* state, uint64_t value) {
        store64(state, value, ((x * 8) + (y * 40)));
    }

    void laneXOR(int x, int y, uint8_t* state, uint64_t xor_value) {
        xor64(state, xor_value, ((x * 8) + (y * 40)));
    }

    void thetaStep(uint8_t* state)
    {
        uint64_t C[5], D;

        for (int x = 0; x < 5; x++) {
            C[x] = laneRead(x, 0, state) ^ laneRead(x, 1, state) ^ laneRead(x, 2, state) ^ laneRead(x, 3, state) ^ laneRead(x, 4, state);
        }

        for (int x = 0; x < 5; x++)
        {
            D = C[(x + 4) % 5] ^ ROL64(C[(x + 1) % 5], 1);

            for (int y = 0; y < 5; y++)
            {
                laneXOR(x, y, state, D);
            }
        }
    }

    void rhoAndPiStep(uint8_t* state)
    {
        uint64_t current, temp;

        uint32_t x = 1, y = 0;
        current = laneRead(x, y, state);
        for (int t = 0; t < 24; t++) {
            uint32_t r = ((t + 1) * (t + 2) / 2) % 64;
            uint32_t Y = (2 * x + 3 * y) % 5; x = y; y = Y;

            temp = laneRead(x, y, state);
            laneWrite(x, y, state, ROL64(current, r));
            current = temp;
        }
    }

    void chiStep(uint8_t* state)
    {
        uint64_t temp[5];

        for (int y = 0; y < 5; y++)
        {
            for (int x = 0; x < 5; x++)
            {
                temp[x] = laneRead(x, y, state);
            }

            for (int x = 0; x < 5; x++)
            {
                laneWrite(x, y, state, temp[x] ^ ((~temp[(x + 1) % 5]) & (temp[(x + 2) % 5])));
            }
        }
    }

    void iotaStep(uint8_t* state, int round) {
        laneXOR(0, 0, state, RC[round % 24]);
    }

    void keccak_permutation_1600(uint8_t* state) {
        for (uint32_t round = 0; round < 24; round++) {
            thetaStep(state);
            rhoAndPiStep(state);
            chiStep(state);
            iotaStep(state, round);
        }
    }


public:
    void keccak(int rate, int capacity, const char* input, int input_length, uint8_t delimitedSuffix, uint8_t* output, int output_length) {
        uint8_t state[200] = { 0 };
        unsigned int rateInBytes = rate / 8;
        unsigned int blockSize = 0;
        unsigned int i;

        if (((rate + capacity) != 1600) || ((rate % 8) != 0))
            return;


        while (input_length > 0) {
            blockSize = MIN(input_length, rateInBytes);
            for (i = 0; i < blockSize; i++)
                state[i] ^= input[i];
            input += blockSize;
            input_length -= blockSize;

            if (blockSize == rateInBytes) {
                keccak_permutation_1600(state);
                blockSize = 0;
            }
        }

        state[blockSize] ^= delimitedSuffix;
        if (((delimitedSuffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
            keccak_permutation_1600(state);
        state[rateInBytes - 1] ^= 0x80;
        keccak_permutation_1600(state);

        while (output_length > 0) {
            blockSize = MIN(output_length, rateInBytes);
            memcpy(output, state, blockSize);
            output += blockSize;
            output_length -= blockSize;

            if (output_length > 0)
                keccak_permutation_1600(state);
        }
    }
    void sha3_512(const char* input, int input_length, uint8_t* output) {
        keccak(576, 1024, input, 3, 0x06, output, 128);
    }

    void sha3_384(const char* input, int input_length, uint8_t* output) {
        keccak(832, 768, input, 3, 0x06, output, 96);

    }

    void sha3_256(const char* input, int input_length, uint8_t* output) {
        keccak(1088, 512, input, 3, 0x06, output, 64);
    }

    void sha3_224(const char* input, int input_length, uint8_t* output) {
        keccak(1152, 448, input, 3, 0x06, output, 56);
    }
};

bool compareOutputs(const uint8_t* output1, const uint8_t* output2, int length) {
    return memcmp(output1, output2, length) == 0;
}

int main()
{
    KeccakC keccak1 = KeccakC();

    const char* input_string = "abc";
    unsigned char output1[32];
    unsigned char output2[32];


    uint8_t input[3] = { 97, 98, 99 };

    keccak1.sha3_256(input_string, 3, output1);

    FIPS202_SHA3_256((const unsigned char*)input_string, 3, output2);

    std::cout << "SHA-3 256-bit Hash output1:";
    for (int i = 0; i < 32; i++) {
        printf("%02x", output1[i]);
    }
    printf("\n");

    std::cout << "SHA-3 256-bit Hash output2:";
    for (int i = 0; i < 32; i++) {
        printf("%02x", output2[i]);
    }
    printf("\n");

    bool isEqual = compareOutputs(output1, output2, 32);
    
    auto start1 = std::chrono::high_resolution_clock::now();
    keccak1.sha3_256(input_string, 3, output1);
    auto end1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration1 = end1 - start1;

    // Measure time for FIPS202_SHA3_256
    auto start2 = std::chrono::high_resolution_clock::now();
    FIPS202_SHA3_256((const unsigned char*)input_string, 3, output2);
    auto end2 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration2 = end2 - start2;

    std::cout << "Outputs are " << (isEqual ? "equal" : "not equal") << std::endl;

    std::cout << "Time taken by keccak1.sha3_256: " << duration1.count() << " seconds" << std::endl;
    std::cout << "Time taken by FIPS202_SHA3_256: " << duration2.count() << " seconds" << std::endl;

    return 0;
}
