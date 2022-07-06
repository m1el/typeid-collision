use rand::{Rand, Rng, SeedableRng};

/// Xoroshiro128+ implementation.
///
/// _Note: Actually just a rewrite from the C-source at
/// http://xoroshiro.di.unimi.it/xoroshiro128plus.c_
pub struct Xoroshiro128Plus {
    state: [u64; 2],
}

impl Xoroshiro128Plus {
    /// This is the jump function for the generator. It is equivalent to 2^64 calls
    /// to next_64(); it can be used to generate 2^64 non-overlapping subsequences for
    /// parallel computations.
    #[allow(dead_code)]
    pub fn jump(&mut self) {
        const JUMP: [u64; 2] = [ 0xbeac0467eba5facb, 0xd86b048b86aa9922 ];

        let mut s0 = 0;
        let mut s1 = 0;
        for &n in JUMP.iter() {
            for b in 0..64 {
                if n & (1 << b) != 0 {
                    s0 ^= self.state[0];
                    s1 ^= self.state[1];
                }
                self.next_u64();
            }
        }

        self.reseed([s0, s1]);
    }
}

impl Rand for Xoroshiro128Plus {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        Self::from_seed(rng.gen())
    }
}

impl Rng for Xoroshiro128Plus {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let s0 = self.state[0];
        let mut s1 = self.state[1];
        let result = s0.wrapping_add(s1);

        s1 ^= s0;
        self.state[0] = s0.rotate_left(55) ^ s1 ^ s1.wrapping_shl(14);
        self.state[1] = s1.rotate_left(36);

        result
    }
}

impl SeedableRng<[u64; 2]> for Xoroshiro128Plus {
    fn reseed(&mut self, seed: [u64; 2]) {
        self.state = seed;
    }

    fn from_seed(seed: [u64; 2]) -> Self {
        Xoroshiro128Plus {
            state: seed,
        }
    }
}
