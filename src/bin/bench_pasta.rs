// Measures (controlled by --kind):
//   - proto : client-side protocol phases (setup, reg, auth, verify)
//   - prim  : crypto primitive microbenches (TOPRF, AEAD, TTG/BLS)
//   - sp    : server-side protocol phases (store, respond, db_get)
//   - net   : network-only simulation (LAN/WAN), excluding server processing time
//   - full  : end-to-end simulation = (measured client time) + (simulated net) + (server proc p50 injected)
// Output format (space-separated):
//   scheme kind op rng_in_timed nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns

#![allow(clippy::needless_range_loop)]

use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::time::Instant;

use blake3;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use curve25519_dalek::scalar::Scalar as RScalar;

use pasta_bench::crypto_core;
use pasta_bench::crypto_pasta as pc;
use pasta_bench::protocols::pasta;

// Stats 
#[derive(Clone, Debug)]
struct Stats {
    n: usize,
    min_ns: u128,
    p50_ns: u128,
    p95_ns: u128,
    max_ns: u128,
    mean_ns: f64,
    stddev_ns: f64,
}

fn compute_stats(mut xs: Vec<u128>) -> Stats {
    xs.sort_unstable();
    let n = xs.len();
    let min_ns = xs[0];
    let max_ns = xs[n - 1];
    let p50_ns = xs[n / 2];
    let p95_ns = xs[(n * 95) / 100];

    let sum: f64 = xs.iter().map(|&x| x as f64).sum();
    let mean_ns = sum / (n as f64);

    let mut var = 0.0;
    for &x in &xs {
        let d = (x as f64) - mean_ns;
        var += d * d;
    }
    let stddev_ns = if n > 1 { (var / ((n - 1) as f64)).sqrt() } else { 0.0 };

    Stats {
        n,
        min_ns,
        p50_ns,
        p95_ns,
        max_ns,
        mean_ns,
        stddev_ns,
    }
}

fn bench_u128(mut f: impl FnMut() -> u128, warmup: usize, samples: usize) -> Stats {
    for _ in 0..warmup {
        black_box(f());
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(f());
    }
    compute_stats(xs)
}

fn time_call_ns<R>(mut f: impl FnMut() -> R) -> u64 {
    let t0 = Instant::now();
    let out = f();
    black_box(out);
    t0.elapsed().as_nanos() as u64
}

fn median_ns(mut xs: Vec<u64>) -> u64 {
    xs.sort_unstable();
    xs[xs.len() / 2]
}

fn write_header(out: &mut BufWriter<File>) -> std::io::Result<()> {
    writeln!(
        out,
        "scheme kind op rng_in_timed nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns"
    )
}

fn write_row(
    out: &mut BufWriter<File>,
    scheme: &str,
    kind: &str,
    op: &str,
    rng_in_timed: bool,
    nsp: usize,
    tsp: usize,
    warmup: usize,
    st: &Stats,
) -> std::io::Result<()> {
    writeln!(
        out,
        "{} {} {} {} {} {} {} {} {} {} {} {} {:.3} {:.3}",
        scheme,
        kind,
        op,
        if rng_in_timed { 1 } else { 0 },
        nsp,
        tsp,
        st.n,
        warmup,
        st.min_ns,
        st.p50_ns,
        st.p95_ns,
        st.max_ns,
        st.mean_ns,
        st.stddev_ns
    )
}

// Parsing helpers

fn parse_list_usize(s: &str) -> Vec<usize> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse::<usize>().expect("bad usize list element"))
        .collect()
}

fn parse_list_u32(s: &str) -> Vec<u32> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse::<u32>().expect("bad u32 list element"))
        .collect()
}

fn parse_list_string_lower(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().to_ascii_lowercase())
        .collect()
}

fn seed_for(tag: &[u8], nsp: usize, tsp: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&(nsp as u64).to_le_bytes());
    h.update(&(tsp as u64).to_le_bytes());
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(out.as_bytes());
    seed
}

// Network simulator 

#[derive(Clone, Copy)]
struct NetProfile {
    name: &'static str,
    one_way_ns: u64,
    jitter_ns: u64,
    bw_bps: u64,
    overhead_bytes: usize,
}

fn ms_to_ns(ms: f64) -> u64 {
    if ms <= 0.0 {
        0
    } else {
        (ms * 1_000_000.0).round() as u64
    }
}

fn mbps_to_bps(mbps: f64) -> u64 {
    if mbps <= 0.0 {
        0
    } else {
        (mbps * 1_000_000.0).round() as u64
    }
}

fn tx_time_ns(bytes: usize, bw_bps: u64) -> u64 {
    if bw_bps == 0 {
        return 0;
    }
    let bits = (bytes as u128) * 8u128;
    let bw = bw_bps as u128;
    let ns = (bits * 1_000_000_000u128 + bw - 1) / bw;
    ns as u64
}

fn sample_jitter(rng: &mut impl RngCore, jitter_ns: u64) -> i64 {
    if jitter_ns == 0 {
        return 0;
    }
    let span = (jitter_ns as u128) * 2 + 1;
    let v = (rng.next_u64() as u128) % span;
    (v as i128 - jitter_ns as i128) as i64
}

fn add_signed_ns(base: u64, delta: i64) -> u64 {
    if delta >= 0 {
        base.saturating_add(delta as u64)
    } else {
        base.saturating_sub((-delta) as u64)
    }
}

fn simulate_parallel_phase(
    k: usize,
    req_payload_bytes: usize,
    resp_payload_bytes: usize,
    proc_ns: u64,
    prof: NetProfile,
    rng: &mut impl RngCore,
) -> u64 {
    if k == 0 {
        return 0;
    }

    let req_total = req_payload_bytes + prof.overhead_bytes;
    let resp_total = resp_payload_bytes + prof.overhead_bytes;

    let tx_req = tx_time_ns(req_total, prof.bw_bps);
    let tx_resp = tx_time_ns(resp_total, prof.bw_bps);

    // Uplink serialization.
    let mut arrivals: Vec<u64> = Vec::with_capacity(k);
    let mut t_uplink_done = 0u64;
    for _ in 0..k {
        t_uplink_done = t_uplink_done.saturating_add(tx_req);
        let j = sample_jitter(rng, prof.jitter_ns);
        let t_arrive = add_signed_ns(t_uplink_done.saturating_add(prof.one_way_ns), j);
        arrivals.push(t_arrive);
    }

    // Providers finish processing.
    let mut ready: Vec<u64> = Vec::with_capacity(k);
    for &a in &arrivals {
        ready.push(a.saturating_add(proc_ns));
    }

    // Responses arrive back at client (before downlink queue).
    let mut down_arr: Vec<u64> = Vec::with_capacity(k);
    for &rdy in &ready {
        let j = sample_jitter(rng, prof.jitter_ns);
        let t = add_signed_ns(rdy.saturating_add(tx_resp).saturating_add(prof.one_way_ns), j);
        down_arr.push(t);
    }

    // Downlink serialization.
    down_arr.sort_unstable();
    let mut t_down_done = 0u64;
    for a in down_arr {
        if t_down_done < a {
            t_down_done = a;
        }
        t_down_done = t_down_done.saturating_add(tx_resp);
    }

    t_down_done
}


// Benchmark helpers (PASTA)

const REQ_BYTES_PER_SERVER: usize = pasta::UID_LEN + pasta::X_LEN + pasta::TOP_REQ_LEN; // (C,x,req)
const RESP_BYTES_PER_SERVER: usize = pasta::TOP_PARTIAL_LEN + (pc::NONCE_LEN + pc::TTG_TOKEN_LEN + pc::TAG_LEN);

#[derive(Clone, Copy, Debug)]
struct ServerProcP50 {
    respond_ns: u64,
    db_get_ns: u64,
    store_ns: u64,
}

fn measure_server_procs_p50(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
) -> ServerProcP50 {
    let fx = pasta::make_fixture(nsp, tsp);
    let srv = &fx.servers[0];

    let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/proc/it", nsp, tsp));
    let it = pasta::make_iter_data(&fx, &mut rng);
    let req_bytes = it.req;

    // Respond
    let mut rng_resp = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/proc/respond_rng", nsp, tsp));
    for _ in 0..warmup {
        let out = if rng_in_timed {
            pasta::respond(srv, fx.c, fx.x, &req_bytes, &mut rng_resp)
        } else {
            pasta::respond_with_nonce(srv, fx.c, fx.x, &req_bytes, &it.nonces[0])
        };
        black_box(out);
    }
    let mut xs = Vec::with_capacity(samples);
    for s in 0..samples {
        xs.push(time_call_ns(|| {
            let out = if rng_in_timed {
                pasta::respond(srv, fx.c, fx.x, &req_bytes, &mut rng_resp)
            } else {
                pasta::respond_with_nonce(srv, fx.c, fx.x, &req_bytes, &it.nonces[0])
            };
            black_box((s, out))
        }));
    }
    let respond_ns = median_ns(xs);

    // DB get
    for _ in 0..warmup {
        black_box(srv.has_record(fx.c));
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            let v = srv.has_record(fx.c);
            black_box(v)
        }));
    }
    let db_get_ns = median_ns(xs);

    // Store 
    let msg = {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/proc/store_msg", nsp, tsp));
        pasta::signup(nsp, tsp, &fx.password, &mut rng).msgs[0].clone()
    };
    let mut srv2 = pasta::PastaServer::new(1, fx.servers[0].ttg_share);
    for _ in 0..warmup {
        srv2.store(fx.c, &msg);
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            srv2.store(fx.c, &msg);
        }));
    }
    let store_ns = median_ns(xs);

    ServerProcP50 {
        respond_ns,
        db_get_ns,
        store_ns,
    }
}


// client protocol phases

fn bench_client_proto(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "pasta";
    let fx = pasta::make_fixture(nsp, tsp);

    // setup 
    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/proto/setup_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = pasta::global_setup(128, nsp, tsp, &mut rng);
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "setup", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // reg (SignUp)
    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/proto/reg_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = pasta::signup(nsp, tsp, &fx.password, &mut rng);
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "reg", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // auth (Request + Finalize), excluding server processing time
    {
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/proto/auth_it", nsp, tsp));
        let mut rng_req = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/proto/auth_req_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let it = pasta::make_iter_data(&fx, &mut rng_it);
                let rho = it.rho;

                // request (timed)
                let t0 = Instant::now();
                let (st_client, creq) = if rng_in_timed {
                    pasta::request(fx.c, &fx.password, fx.x, &fx.t_set, &mut rng_req)
                } else {
                    pasta::request_with_rho(fx.c, &fx.password, fx.x, &fx.t_set, rho)
                };
                let t_req = t0.elapsed();

                // server responses (not timed)
                let mut resps = Vec::with_capacity(tsp);
                for j in 0..tsp {
                    let srv = &fx.servers[j];
                    let resp = pasta::respond_with_nonce(srv, fx.c, fx.x, &creq.req, &it.nonces[j])
                        .expect("fixture should have record");
                    resps.push(resp);
                }
                black_box(&resps);

                // finalize (timed)
                let t1 = Instant::now();
                let tk = pasta::finalize(&st_client, fx.x, &resps).unwrap();
                black_box(tk);
                let t_fin = t1.elapsed();

                (t_req + t_fin).as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "auth", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // verify (TTG.Verify)
    {
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/proto/ver_it", nsp, tsp));
        let st = bench_u128(
            || {
                let it = pasta::make_iter_data(&fx, &mut rng_it);
                let (st_client, creq) = pasta::request_with_rho(fx.c, &fx.password, fx.x, &fx.t_set, it.rho);
                let mut resps = Vec::with_capacity(tsp);
                for j in 0..tsp {
                    let srv = &fx.servers[j];
                    let resp = pasta::respond_with_nonce(srv, fx.c, fx.x, &creq.req, &it.nonces[j]).unwrap();
                    resps.push(resp);
                }
                let tk = pasta::finalize(&st_client, fx.x, &resps).unwrap();

                let t0 = Instant::now();
                let ok = pasta::verify(&fx.vk, fx.c, fx.x, &tk);
                black_box(ok);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "verify", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    Ok(())
}


// server protocol phases


fn bench_server_phases(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "pasta";
    let fx = pasta::make_fixture(nsp, tsp);
    let srv0 = &fx.servers[0];

    // db_get
    {
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let ok = srv0.has_record(fx.c);
                black_box(ok);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "sp", "db_get", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // store
    {
        let msg = {
            let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/sp/store_msg", nsp, tsp));
            pasta::signup(nsp, tsp, &fx.password, &mut rng).msgs[0].clone()
        };
        let mut srv = pasta::PastaServer::new(1, fx.servers[0].ttg_share);
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                srv.store(fx.c, &msg);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "sp", "store", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // respond
    {
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/sp/respond_it", nsp, tsp));
        let it = pasta::make_iter_data(&fx, &mut rng_it);
        let req_bytes = it.req;
        let mut rng_resp = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/sp/respond_rng", nsp, tsp));

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = if rng_in_timed {
                    pasta::respond(srv0, fx.c, fx.x, &req_bytes, &mut rng_resp)
                } else {
                    pasta::respond_with_nonce(srv0, fx.c, fx.x, &req_bytes, &it.nonces[0])
                };
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "sp", "respond", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    Ok(())
}


// primitives


fn bench_primitives(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "pasta";
    let fx = pasta::make_fixture(nsp, tsp);

    // TOPRF: hash_to_point
    {
        let pwd = fx.password.clone();
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let p = crypto_core::hash_to_point(&pwd);
                black_box(p);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "prim", "top_hash_to_point", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // TOPRF: encode (hash_to_point + mul)
    {
        let pwd = fx.password.clone();
        let rho = RScalar::from(7u64);
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let req = pc::toprf_encode(&pwd, rho);
                black_box(req.compress());
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "prim", "top_encode", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // TOPRF: client combine (given precomputed partials)
    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/prim/top_combine", nsp, tsp));
        let rho = crypto_core::random_scalar(&mut rng);
        let req = pc::toprf_encode(&fx.password, rho);
        let ids: Vec<u32> = (1..=tsp as u32).collect();
        let lambdas = crypto_core::lagrange_coeffs_at_zero(&ids);
        let mut partials = Vec::with_capacity(tsp);
        for j in 0..tsp {
            let share = fx.servers[j].get_record(fx.c).unwrap().k_i;
            partials.push(pc::toprf_eval_share(share, &req));
        }

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let h = crypto_core::toprf_client_eval_from_partials(&fx.password, rho, &partials, &lambdas);
                black_box(h);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "prim", "top_combine", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // H(h||i)
    {
        let h = [42u8; 32];
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = pc::hash_hi(&h, 1);
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "prim", "hash_hi", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // SKE: XChaCha encrypt 48 bytes
    {
        let key = [7u8; 32];
        let pt = [9u8; pc::TTG_TOKEN_LEN];
        let aad: [u8; 0] = [];
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/prim/aead_enc_rng", nsp, tsp));
        let nonce = [3u8; crypto_core::NONCE_LEN];

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let blob = if rng_in_timed {
                    pc::xchacha_encrypt_detached(&key, &aad, &pt, &mut rng)
                } else {
                    pc::xchacha_encrypt_detached_with_nonce(&key, &aad, &pt, &nonce)
                };
                black_box(blob);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "prim", "aead_encrypt", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // SKE: XChaCha decrypt 48 bytes
    {
        let key = [7u8; 32];
        let pt = [9u8; pc::TTG_TOKEN_LEN];
        let aad: [u8; 0] = [];
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/prim/aead_dec_rng", nsp, tsp));
        let blob = pc::xchacha_encrypt_detached(&key, &aad, &pt, &mut rng);

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = pc::xchacha_decrypt_detached(&key, &aad, &blob).unwrap();
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "prim", "aead_decrypt", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // TTG: hash_to_g1
    {
        let msg = [5u8; pasta::UID_LEN + pasta::X_LEN];
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let h = pc::ttg_hash_to_g1(&msg);
                black_box(h);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "prim", "ttg_hash_to_g1", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // TTG: part_eval
    {
        let msg = [5u8; pasta::UID_LEN + pasta::X_LEN];
        let share = fx.servers[0].ttg_share;
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let y = pc::ttg_part_eval(&share, &msg);
                black_box(y);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "prim", "ttg_part_eval", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // TTG: combine
    {
        let msg = [5u8; pasta::UID_LEN + pasta::X_LEN];
        let ids: Vec<u32> = (1..=tsp as u32).collect();
        let partials: Vec<_> = (0..tsp)
            .map(|j| pc::ttg_part_eval(&fx.servers[j].ttg_share, &msg))
            .collect();

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let tk = pc::ttg_combine(&ids, &partials);
                black_box(tk);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "prim", "ttg_combine", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    // TTG: verify
    {
        let msg = [5u8; pasta::UID_LEN + pasta::X_LEN];
        let ids: Vec<u32> = (1..=tsp as u32).collect();
        let partials: Vec<_> = (0..tsp)
            .map(|j| pc::ttg_part_eval(&fx.servers[j].ttg_share, &msg))
            .collect();
        let tk = pc::ttg_combine(&ids, &partials);

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let ok = pc::ttg_verify(&fx.vk, &msg, &tk);
                black_box(ok);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "prim", "ttg_verify", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    Ok(())
}


// net-only and full


fn bench_net(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    prof: NetProfile,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "pasta";
    let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/net", nsp, tsp));

    for _ in 0..warmup {
        let ns = simulate_parallel_phase(
            tsp,
            REQ_BYTES_PER_SERVER,
            RESP_BYTES_PER_SERVER,
            0,
            prof,
            &mut rng,
        );
        black_box(ns);
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let ns = simulate_parallel_phase(
            tsp,
            REQ_BYTES_PER_SERVER,
            RESP_BYTES_PER_SERVER,
            0,
            prof,
            &mut rng,
        );
        xs.push(ns as u128);
    }
    let st = compute_stats(xs);
    // op name encodes the profile
    write_row(
        out,
        scheme,
        "net",
        &format!("auth_{}", prof.name),
        false,
        nsp,
        tsp,
        warmup,
        &st,
    )
}

fn bench_full(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    prof: NetProfile,
    proc_warmup: usize,
    proc_samples: usize,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "pasta";

    // Calibrate server p50 processing time (respond)
    let proc = measure_server_procs_p50(nsp, tsp, proc_warmup, proc_samples, rng_in_timed);

    let fx = pasta::make_fixture(nsp, tsp);
    let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/full/it", nsp, tsp));
    let mut rng_net = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/full/net", nsp, tsp));
    let mut rng_req = ChaCha20Rng::from_seed(seed_for(b"bench_pasta/full/req_rng", nsp, tsp));

    let st = bench_u128(
        || {
            let it = pasta::make_iter_data(&fx, &mut rng_it);
            let rho = it.rho;

            // client CPU time (request + finalize), excluding server processing
            let t0 = Instant::now();
            let (st_client, creq) = if rng_in_timed {
                pasta::request(fx.c, &fx.password, fx.x, &fx.t_set, &mut rng_req)
            } else {
                pasta::request_with_rho(fx.c, &fx.password, fx.x, &fx.t_set, rho)
            };
            let t_req = t0.elapsed();

            // server responses (not timed)
            let mut resps = Vec::with_capacity(tsp);
            for j in 0..tsp {
                let srv = &fx.servers[j];
                let resp = pasta::respond_with_nonce(srv, fx.c, fx.x, &creq.req, &it.nonces[j]).unwrap();
                resps.push(resp);
            }

            let t1 = Instant::now();
            let tk = pasta::finalize(&st_client, fx.x, &resps).unwrap();
            black_box(tk);
            let t_fin = t1.elapsed();
            let client_ns = (t_req + t_fin).as_nanos() as u64;

            // net + server proc
            let net_ns = simulate_parallel_phase(
                tsp,
                REQ_BYTES_PER_SERVER,
                RESP_BYTES_PER_SERVER,
                proc.respond_ns,
                prof,
                &mut rng_net,
            );

            (client_ns as u128) + (net_ns as u128)
        },
        warmup,
        samples,
    );

    write_row(
        out,
        scheme,
        "full",
        &format!("auth_{}", prof.name),
        rng_in_timed,
        nsp,
        tsp,
        warmup,
        &st,
    )
}


// main

fn usage() -> &'static str {
    "bench_pasta usage:\n\
  cargo run --release --bin bench_pasta -- [flags]\n\
\n\
Flags:\n\
  --kind proto|prim|sp|net|full|all         (default: all)\n\
  --net lan|wan|all                         (default: all; only for kind net/full)\n\
  --nsp 20,40,60                            (default: 20,40,60)\n\
  --tsp 5,10,20                             (absolute; default: empty)\n\
  --tsp-pct 20,50,80                        (percent of nsp; rounded up; clamped; default: 50)\n\
  --sample-size N                           (default: 200)\n\
  --warmup-iters N                          (default: 50)\n\
  --out FILE                                (default: pasta_bench.txt)\n\
  --rng-in-timed                             (include RNG costs in timed regions)\n\
  --lan-rtt-ms / --lan-jitter-ms / --lan-bw-mbps / --overhead-bytes\n\
  --wan-rtt-ms / --wan-jitter-ms / --wan-bw-mbps\n\
  --proc-warmup N / --proc-samples N        (only for kind full; server p50 calibration)\n\
  --help"
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut kinds = vec!["all".to_string()];
    let mut nets = vec!["all".to_string()];
    let mut nsp_list = vec![20usize, 40, 60];
    let mut tsp_list: Vec<usize> = Vec::new();
    let mut tsp_pct_list = vec![50u32];
    let mut samples = 200usize;
    let mut warmup = 50usize;
    let mut out_path = "pasta_bench.txt".to_string();
    let mut rng_in_timed = false;

    let mut lan_rtt_ms = 2.0;
    let mut lan_jitter_ms = 0.2;
    let mut lan_bw_mbps = 1000.0;

    let mut wan_rtt_ms = 80.0;
    let mut wan_jitter_ms = 5.0;
    let mut wan_bw_mbps = 100.0;

    let mut overhead_bytes = 40usize;

    let mut proc_warmup = 200usize;
    let mut proc_samples = 400usize;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("{}", usage());
                return Ok(());
            }
            "--kind" => {
                i += 1;
                kinds = parse_list_string_lower(&args[i]);
            }
            "--net" => {
                i += 1;
                nets = parse_list_string_lower(&args[i]);
            }
            "--nsp" => {
                i += 1;
                nsp_list = parse_list_usize(&args[i]);
            }
            "--tsp" => {
                i += 1;
                tsp_list = parse_list_usize(&args[i]);
            }
            "--tsp-pct" => {
                i += 1;
                tsp_pct_list = parse_list_u32(&args[i]);
            }
            "--sample-size" => {
                i += 1;
                samples = args[i].parse().expect("bad sample-size");
            }
            "--warmup-iters" => {
                i += 1;
                warmup = args[i].parse().expect("bad warmup-iters");
            }
            "--out" => {
                i += 1;
                out_path = args[i].clone();
            }
            "--rng-in-timed" => {
                rng_in_timed = true;
            }
            "--lan-rtt-ms" => {
                i += 1;
                lan_rtt_ms = args[i].parse().expect("bad lan-rtt-ms");
            }
            "--lan-jitter-ms" => {
                i += 1;
                lan_jitter_ms = args[i].parse().expect("bad lan-jitter-ms");
            }
            "--lan-bw-mbps" => {
                i += 1;
                lan_bw_mbps = args[i].parse().expect("bad lan-bw-mbps");
            }
            "--wan-rtt-ms" => {
                i += 1;
                wan_rtt_ms = args[i].parse().expect("bad wan-rtt-ms");
            }
            "--wan-jitter-ms" => {
                i += 1;
                wan_jitter_ms = args[i].parse().expect("bad wan-jitter-ms");
            }
            "--wan-bw-mbps" => {
                i += 1;
                wan_bw_mbps = args[i].parse().expect("bad wan-bw-mbps");
            }
            "--overhead-bytes" => {
                i += 1;
                overhead_bytes = args[i].parse().expect("bad overhead-bytes");
            }
            "--proc-warmup" => {
                i += 1;
                proc_warmup = args[i].parse().expect("bad proc-warmup");
            }
            "--proc-samples" => {
                i += 1;
                proc_samples = args[i].parse().expect("bad proc-samples");
            }
            other => {
                eprintln!("Unknown flag: {}\n\n{}", other, usage());
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let prof_lan = NetProfile {
        name: "lan",
        one_way_ns: ms_to_ns(lan_rtt_ms / 2.0),
        jitter_ns: ms_to_ns(lan_jitter_ms),
        bw_bps: mbps_to_bps(lan_bw_mbps),
        overhead_bytes,
    };
    let prof_wan = NetProfile {
        name: "wan",
        one_way_ns: ms_to_ns(wan_rtt_ms / 2.0),
        jitter_ns: ms_to_ns(wan_jitter_ms),
        bw_bps: mbps_to_bps(wan_bw_mbps),
        overhead_bytes,
    };

    let mut net_profiles: Vec<NetProfile> = Vec::new();
    if nets.contains(&"all".to_string()) {
        net_profiles.push(prof_lan);
        net_profiles.push(prof_wan);
    } else {
        for n in &nets {
            match n.as_str() {
                "lan" => net_profiles.push(prof_lan),
                "wan" => net_profiles.push(prof_wan),
                _ => {}
            }
        }
    }

    let file = File::create(&out_path)?;
    let mut out = BufWriter::new(file);
    write_header(&mut out)?;

    let kinds_all = kinds.contains(&"all".to_string());
    let want_proto = kinds_all || kinds.contains(&"proto".to_string());
    let want_prim = kinds_all || kinds.contains(&"prim".to_string());
    let want_sp = kinds_all || kinds.contains(&"sp".to_string());
    let want_net = kinds_all || kinds.contains(&"net".to_string());
    let want_full = kinds_all || kinds.contains(&"full".to_string());

    for &nsp in &nsp_list {
        // Build tsp list for this nsp.
        let mut tsps: Vec<usize> = Vec::new();
        tsps.extend(tsp_list.iter().copied().filter(|&t| t >= 1 && t <= nsp));
        for pct in &tsp_pct_list {
            let mut t = ((nsp as u64) * (*pct as u64) + 99) / 100; // ceil
            if t < 1 {
                t = 1;
            }
            if t > nsp as u64 {
                t = nsp as u64;
            }
            tsps.push(t as usize);
        }
        tsps.sort_unstable();
        tsps.dedup();

        for &tsp in &tsps {
            if want_proto {
                bench_client_proto(nsp, tsp, warmup, samples, rng_in_timed, &mut out)?;
            }
            if want_sp {
                bench_server_phases(nsp, tsp, warmup, samples, rng_in_timed, &mut out)?;
            }
            if want_prim {
                bench_primitives(nsp, tsp, warmup, samples, rng_in_timed, &mut out)?;
            }
            if want_net {
                for prof in &net_profiles {
                    bench_net(nsp, tsp, warmup, samples, *prof, &mut out)?;
                }
            }
            if want_full {
                for prof in &net_profiles {
                    bench_full(
                        nsp,
                        tsp,
                        warmup,
                        samples,
                        rng_in_timed,
                        *prof,
                        proc_warmup,
                        proc_samples,
                        &mut out,
                    )?;
                }
            }
        }
    }

    out.flush()?;
    eprintln!("wrote {}", out_path);
    Ok(())
}
