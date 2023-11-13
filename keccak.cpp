#include <iostream>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))


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
            laneWrite(x, y, state, temp[x] ^ ((~temp[(x + 1) % 5]) & (temp[(x + 2) % 5])) );
        }
    }
}

void iotaStep(uint8_t* state, int round) {
    laneXOR(0, 0, state, RC[round % 24]);
}

void keccak_permutation_1600(uint8_t*state) {
    for (uint32_t round = 0; round < 24; round++) {
        thetaStep(state);
        rhoAndPiStep(state);
        chiStep(state);
        iotaStep(state, round);
    }
}


void keccak(int rate, int capacity,const char* input, int input_length, uint8_t delimitedSuffix, uint8_t * output,int output_length) {
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

int main()
{
    const char* input_string = "abc";
    unsigned char output[32];

    uint8_t input[3] = { 97, 98, 99 };

    keccak(1088, 512, input_string, 3, 0x06, output, 64);

    std::cout << ("SHA-3 256-bit Hash:");
    for (int i = 0; i < 32; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");


    return 0;
}
