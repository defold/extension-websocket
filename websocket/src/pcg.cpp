#include "websocket.h"

// https://www.pcg-random.org/using-pcg-c-basic.html

namespace dmWebsocket
{
    uint32_t pcg32_random_r(pcg32_random_t* rng)
    {
        uint64_t oldstate = rng->state;
        rng->state = oldstate * 6364136223846793005ULL + rng->inc;
        uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
        uint32_t rot = oldstate >> 59u;
        return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
    }

    void pcg32_srandom_r(pcg32_random_t* rng, uint64_t initstate, uint64_t initseq)
    {
        rng->state = 0U;
        rng->inc = (initseq << 1u) | 1u;
        pcg32_random_r(rng);
        rng->state += initstate;
        pcg32_random_r(rng);
    }
}