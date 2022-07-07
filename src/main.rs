#![feature(hasher_prefixfree_extras, maybe_uninit_uninit_array)]

mod sip128;
mod stable_hasher;
mod xoroshiro;

use rand::{Rng, SeedableRng};
use std::collections::hash_map::{HashMap, Entry};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::hash::Hasher;

use crate::xoroshiro::Xoroshiro128Plus;
use crate::stable_hasher::{HashStable, HashingControls, StableHasher};

const IN_PLAYGROUND_WRAPPER: bool = true;
const I_WANT_TO_DEBUG_DEF_ID: bool = false;
const DEFAULT_TRAIL_MASK: u64 = 0x3ffff;

fn hash_of<T: HashStable<CTX>, CTX>(hcx: &mut CTX, val: T) -> (u64, u64) {
    let mut hasher = StableHasher::new();
    val.hash_stable(hcx, &mut hasher);
    hasher.finalize()
}

fn make_mod_id(crate_name: &str, is_exe: bool, version: &str, mut metadata: Vec<String>) -> (u64, u64) {
    let mut hcx = HashingControls { hash_spans: false };
    let mut hasher = StableHasher::new();
    hasher.write_str(crate_name);
    metadata.sort();
    metadata.dedup();
    hasher.write(b"metadata");
    for s in &metadata {
        hasher.write_usize(s.len());
        hasher.write(s.as_bytes());
    }

    hasher.write(if is_exe { b"exe" } else { b"lib" });
    hasher.write(version.as_bytes());

    let crate_id = hasher.finalize().0;
    let mod_id = hash_of(&mut hcx, (crate_id, 0_u64, 0_isize, 0_u32)).0;
    if IN_PLAYGROUND_WRAPPER {
        let mut hasher = StableHasher::new();
        (crate_id, mod_id).hash_stable(&mut hcx, &mut hasher);
        hasher.write_isize(6); // discriminator
        hasher.write_str("main");
        hasher.write_u32(0);
        let main_id = hasher.finalize().0;
        (crate_id, main_id)
    } else {
        (crate_id, mod_id)
    }
}

#[allow(dead_code)]
fn type_id_of_struct(mod_id: (u64, u64), name: &str, field: &str) -> u64 {
    let mut hcx = HashingControls { hash_spans: false };
    let crate_id = mod_id.0;
    let struct_did = {
        let mut hasher = StableHasher::new();
        mod_id.hash_stable(&mut hcx, &mut hasher);
        hasher.write_isize(5); // discriminator
        hasher.write_str(name);
        hasher.write_u32(0);
        (crate_id, hasher.finalize().0)
    };
    let field_shuffle_seed = struct_did.0.wrapping_mul(3).wrapping_add(struct_did.1);
    let field_did = {
        let mut hasher = StableHasher::new();
        struct_did.hash_stable(&mut hcx, &mut hasher);
        hasher.write_isize(6); // discriminator
        hasher.write_str(field);
        hasher.write_u32(0);
        (crate_id, hasher.finalize().0)
    };
    // println!("struct_did={:x?}", struct_did);
    // println!("field_did={:x?}", field_did);
    let adt_hash = {
        let mut hasher = StableHasher::new();
        // DefId
        struct_did.hash_stable(&mut hcx, &mut hasher);
        hasher.write_usize(1);
        struct_did.hash_stable(&mut hcx, &mut hasher);
        hasher.write_u8(0);
        name.as_bytes().hash_stable(&mut hcx, &mut hasher);
        // Variants
        hasher.write_isize(1);
        hasher.write_u32(0);
        hasher.write_usize(1);
        field_did.hash_stable(&mut hcx, &mut hasher);
        hasher.write_usize(field.len());
        hasher.write(field.as_bytes());
        // visibility
        hasher.write_isize(0);
        // scope of visibility
        // mod_id.hash_stable(&mut hcx, &mut hasher); 
        hasher.write_isize(2);
        hasher.write_u32(0);
        // AdtFlags
        hasher.write_u32(4);
        // ReprOptions
        hasher.write_u8(0);
        hasher.write_u8(0);
        hasher.write_u8(0);
        hasher.write_u8(0);
        hasher.write_u64(field_shuffle_seed);
        hasher.finalize()
    };
    let substs_hash = hash_of(&mut hcx, 0_usize);
    let ty_hash = hash_of(&mut hcx, (5_isize, adt_hash, substs_hash));
    hash_of(&mut hcx, ty_hash).0
}

#[allow(dead_code)]
fn field_did(mod_id: (u64, u64), name: &str, field: &str) -> u64 {
    let mut hcx = HashingControls { hash_spans: false };
    let crate_id = mod_id.0;
    let struct_did = {
        let mut hasher = StableHasher::new();
        mod_id.hash_stable(&mut hcx, &mut hasher);
        hasher.write_isize(5); // discriminator
        hasher.write_str(name);
        hasher.write_u32(0);
        (crate_id, hasher.finalize().0)
    };
    let field_did = {
        let mut hasher = StableHasher::new();
        struct_did.hash_stable(&mut hcx, &mut hasher);
        hasher.write_isize(6); // discriminator
        hasher.write_str(field);
        hasher.write_u32(0);
        (crate_id, hasher.finalize().0)
    };
    field_did.1
}

type Point = u64;

fn write_hex(dst: &mut[u8], value: u64) {
    fn hex(x: u64) -> u8 {
        assert!(x <= 15, "YOU LIED");
        (x as u8) + if x <= 9 { b'0' } else { b'a' - 10 }
    }
    for ii in 0..8 {
        let byte = value >> (64 - (ii + 1) * 8);
        let lo = hex(byte & 0xf);
        let hi = hex((byte & 0xf0) >> 4);
        dst[ii * 2] = hi;
        dst[ii * 2 + 1] = lo;
    }
}

/// This function should split evenly between two hash paths
/// which you're trying to collide.
fn bifurcation_criterion(state: Point) -> bool {
    state & 1 != 0
}

/// Calculate the next point on the hash 
fn next_point(mod_id: (u64, u64), state: Point) -> Point {
    let name = if bifurcation_criterion(state) { "Foo" } else { "Bar" };

    let mut data = *b"x0000000000000000";
    write_hex(&mut data[1..], state);

    let field_name = core::str::from_utf8(&data[..]).unwrap();
    // println!("field_name: {}", field_name);
    type_id_of_struct(mod_id, name, field_name)
    // field_did(name, field_name)
}

/// Given two starting points, find the first collision point on a trail
fn find_collision(mod_id: (u64, u64), mut a: Point, len_a: u64, mut b: Point, len_b: u64,) -> (Point, Point) {
    // Make the trails the same length by throwing away some of the start
    let _len = if len_a > len_b {
        for _ in 0..(len_a - len_b) {
            a = next_point(mod_id, a);
        }
        len_b
    } else {
        for _ in 0..(len_b - len_a) {
            b = next_point(mod_id, b);
        }
        len_a
    };

    // find the collision point
    loop {
        let pa = a;
        let pb = b;
        a = next_point(mod_id, a);
        b = next_point(mod_id, b);
        if a == b {
            return (pa, pb);
        }
    }
}

fn main() {
    let mod_id = make_mod_id("playground", true,
        "1.64.0-nightly (7665c3543 2022-07-06)",
        vec!["a0ecb98bfb1b38c8".to_owned()],
    );

    if I_WANT_TO_DEBUG_DEF_ID {
        println!("mod def_hash: {:x?}", mod_id);

        let bar_type_id = type_id_of_struct(mod_id, "Bar", "xa4577f991bd8c53a");
        let foo_type_id = type_id_of_struct(mod_id, "Foo", "x367b9e54d8794eed");
        println!("bar type_id: {:x?}", bar_type_id);
        println!("foo type_id: {:x?}", foo_type_id);
        // println!("next point: {:x}", next_point(mod_id, 0x7543497aa1a3f392));
        // println!("next point: {:x}", next_point(mod_id, 0xaf3f5aafee501b05));

        // let mut hasher = StableHasher::new();
        // 0usize.hash_stable(&mut hcx, &mut hasher);
        // println!("{:x?}", hasher.finalize());

        // println!("next_point: {:x?}", next_point(0x0000000000000000));
    } else {
        static TRAILS: AtomicU64 = AtomicU64::new(0);
        static SYNC_POINT: AtomicUsize = AtomicUsize::new(0);
        static HASH_COUNT: AtomicU64= AtomicU64::new(0);
        static CONTENTIONS: AtomicUsize = AtomicUsize::new(0);
        static TRAIL_MASK: AtomicU64 = AtomicU64::new(DEFAULT_TRAIL_MASK);
        static ROBIN_HOOD: AtomicU64 = AtomicU64::new(0);
        static LOOPS: AtomicU64 = AtomicU64::new(0);
        static COLLISIONS: AtomicU64 = AtomicU64::new(0);

        let trails = HashMap::<Point, Vec<(Point, u64)>>::new();
        let trails = Arc::new(Mutex::new(trails));
        let thread_count = num_cpus::get() as u64;


        // SYNC_POINT.store(1, Ordering::SeqCst);
        let mut workers = Vec::new();
        for worker in 0..thread_count {
            let trails = trails.clone();
            let mut worker_rng = Xoroshiro128Plus::from_seed([0x2337133713371338 + worker, 0x2337133713371337 + worker * 2]);
            workers.push(std::thread::spawn(move || loop {
                // wait to start work
                // while SYNC_POINT.load(Ordering::SeqCst) != 0 {
                //     std::hint::spin_loop();
                // }

                let trail_mask = TRAIL_MASK.load(Ordering::SeqCst);
                'outer: loop {
                    let start: Point = worker_rng.next_u64();
                    let mut trail_steps = 0;
                    let mut value = start;
                    // Generate a trail.
                    // The loop will return a distinguishing point.
                    let hash = loop {
                        if SYNC_POINT.load(Ordering::Relaxed) != 0 { break 'outer }
                        trail_steps += 1;

                        let hash = next_point(mod_id, value);
                        // How many hashes to put in the same trail. This is 1/theta.
                        if hash & trail_mask == 0 {
                            TRAILS.fetch_add(1, Ordering::Relaxed);
                            HASH_COUNT.fetch_add(trail_steps, Ordering::Relaxed);
                            break hash;
                        }
                        // give up on this trail
                        if trail_steps > 20 * trail_mask {
                            LOOPS.fetch_add(1, Ordering::Relaxed);
                            HASH_COUNT.fetch_add(trail_steps, Ordering::Relaxed);
                            continue 'outer;
                        }
                        value = hash;
                    };

                    let mut trails = if let Ok(lock) = trails.try_lock() {
                        lock
                    } else {
                        CONTENTIONS.fetch_add(1, Ordering::Relaxed);
                        trails.lock().unwrap()
                    };

                    let new_trail = (start, trail_steps);
                    // let mut collided = false;
                    match trails.entry(hash) {
                        Entry::Occupied(mut entry) => {
                            let trails = entry.get_mut();
                            for (old_start, old_len) in trails.iter() {
                                if hash == *old_start {
                                    ROBIN_HOOD.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                let (ca, cb) = find_collision(mod_id, *old_start, *old_len, start, trail_steps);
                                if bifurcation_criterion(ca) == bifurcation_criterion(cb) {
                                    println!("found self-collision! ca={:x?} cb={:x?}", ca, cb);
                                } else {
                                    println!("found a good collision! ca={:x?} cb={:x?}", ca, cb);
                                }
                                COLLISIONS.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            trails.push(new_trail);
                            // collided = true;
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(vec![new_trail]);
                        }
                    };
                }

                // SYNC_POINT.fetch_add(1, Ordering::SeqCst); 
            }));
        }
        let start = std::time::Instant::now();
        for _ in 0.. {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let stat_time = start.elapsed().as_secs_f64();
            let loops = LOOPS.load(Ordering::Relaxed);
            let contentions = CONTENTIONS.load(Ordering::Relaxed);
            let collisions = COLLISIONS.load(Ordering::Relaxed);
            let hashes = HASH_COUNT.load(Ordering::Relaxed);
            let robin_hood = ROBIN_HOOD.load(Ordering::Relaxed);
            println!("{:4.0},{:4.0},{:2.5},{:4},{:4},{:4}",
                     (hashes as f64) / stat_time,
                     (hashes as f64) / (collisions as f64),
                     (stat_time / 1000.0) / (collisions as f64),
                     (loops as f64) / (collisions as f64),
                     (contentions as f64) / (stat_time as f64 / 1000.0),
                     (robin_hood as f64) / (collisions as f64));
        }

        for worker in workers {
            worker.join().unwrap();
        }
    }
}
