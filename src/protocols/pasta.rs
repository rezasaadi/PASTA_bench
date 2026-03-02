#![allow(clippy::needless_range_loop)]
use std::collections::HashMap;
use blake3;
use curve25519_dalek::{
    ristretto::CompressedRistretto,
    scalar::Scalar as RScalar,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use crate::crypto_core;
use crate::crypto_pasta as pc;

pub const UID_LEN: usize = 32;
pub const X_LEN: usize = 32;
pub const TOP_REQ_LEN: usize = 32; 
pub const TOP_PARTIAL_LEN: usize = 32; 

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientId(pub [u8; UID_LEN]);

#[derive(Clone, Copy, Debug)]
pub struct PublicParams {
    pub kappa: usize,
    pub n: usize,
    pub t: usize,
}

// Setup

#[derive(Clone)]
pub struct GlobalSetupOut {
    pub ttg_shares: Vec<(u32, pc::TtgShare)>,
    pub vk: pc::TtgVk,
    pub pp: PublicParams,
}

pub fn global_setup(kappa: usize, n: usize, t: usize, rng: &mut impl RngCore) -> GlobalSetupOut {
    let (ttg_shares, vk) = pc::ttg_setup(n, t, rng);
    GlobalSetupOut {
        ttg_shares,
        vk,
        pp: PublicParams { kappa, n, t },
    }
}


// Registration: SignUp + Store


#[derive(Clone, Debug)]
pub struct SignupMsg {
    pub server_id: u32,
    pub k_i: RScalar,
    pub h_i: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct SignupOut {
    pub k0: RScalar,
    pub msgs: Vec<SignupMsg>,
}

pub fn signup(n: usize, t: usize, password: &[u8], rng: &mut impl RngCore) -> SignupOut {
    let (k0, shares) = crypto_core::toprf_gen(n, t, rng);
    let h = pc::toprf_direct(password, k0);

    let mut msgs = Vec::with_capacity(n);
    for (sid, k_i) in shares {
        let h_i = pc::hash_hi(&h, sid);
        msgs.push(SignupMsg {
            server_id: sid,
            k_i,
            h_i,
        });
    }

    SignupOut { k0, msgs }
}

#[derive(Clone, Debug)]
pub struct ServerRecord {
    pub k_i: RScalar,
    pub h_i: [u8; 32],
}

#[derive(Clone)]
pub struct PastaServer {
    pub id: u32,
    pub ttg_share: pc::TtgShare,
    records: HashMap<ClientId, ServerRecord>,
}

impl PastaServer {
    pub fn new(id: u32, ttg_share: pc::TtgShare) -> Self {
        Self {
            id,
            ttg_share,
            records: HashMap::new(),
        }
    }

    pub fn store(&mut self, c: ClientId, msg: &SignupMsg) {
        debug_assert_eq!(self.id, msg.server_id);
        self.records.insert(
            c,
            ServerRecord {
                k_i: msg.k_i,
                h_i: msg.h_i,
            },
        );
    }

    pub fn has_record(&self, c: ClientId) -> bool {
        self.records.contains_key(&c)
    }

    pub fn get_record(&self, c: ClientId) -> Option<&ServerRecord> {
        self.records.get(&c)
    }
}

// Sign-on / TG: Request + Respond + Finalize

#[derive(Clone, Debug)]
pub struct ClientState {
    pub c: ClientId,
    pub password: Vec<u8>,
    pub rho: RScalar,
    pub t_set: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct ClientRequest {
    pub c: ClientId,
    pub x: [u8; X_LEN],
    pub req: [u8; TOP_REQ_LEN],
}

pub fn request(
    c: ClientId,
    password: &[u8],
    x: [u8; X_LEN],
    t_set: &[u32],
    rng: &mut impl RngCore,
) -> (ClientState, ClientRequest) {
    let rho = crypto_core::random_scalar(rng);
    request_with_rho(c, password, x, t_set, rho)
}

pub fn request_with_rho(
    c: ClientId,
    password: &[u8],
    x: [u8; X_LEN],
    t_set: &[u32],
    rho: RScalar,
) -> (ClientState, ClientRequest) {
    assert!(!t_set.is_empty());
    let req_point = pc::toprf_encode(password, rho);
    let req_bytes = req_point.compress().to_bytes();

    let st = ClientState {
        c,
        password: password.to_vec(),
        rho,
        t_set: t_set.to_vec(),
    };
    let req = ClientRequest { c, x, req: req_bytes };
    (st, req)
}

#[derive(Clone, Debug)]
pub struct ServerResponse {
    pub server_id: u32,
    pub z_i: [u8; TOP_PARTIAL_LEN],
    pub ctxt_i: pc::CtBlob<{pc::TTG_TOKEN_LEN}>,
}

pub fn respond(
    srv: &PastaServer,
    c: ClientId,
    x: [u8; X_LEN],
    req_bytes: &[u8; TOP_REQ_LEN],
    rng: &mut impl RngCore,
) -> Option<ServerResponse> {
    let rec = srv.records.get(&c)?;
    let req_point = CompressedRistretto(*req_bytes).decompress()?;

    let z_i = pc::toprf_eval_share(rec.k_i, &req_point);
    let z_bytes = z_i.compress().to_bytes();

    let mut msg = [0u8; UID_LEN + X_LEN];
    msg[0..UID_LEN].copy_from_slice(&c.0);
    msg[UID_LEN..UID_LEN + X_LEN].copy_from_slice(&x);
    let y_i = pc::ttg_part_eval(&srv.ttg_share, &msg);
    let y_bytes = pc::ttg_partial_to_bytes(&y_i);

    let aad: [u8; 0] = [];
    let ctxt_i = pc::xchacha_encrypt_detached(&rec.h_i, &aad, &y_bytes, rng);

    Some(ServerResponse {
        server_id: srv.id,
        z_i: z_bytes,
        ctxt_i,
    })
}

pub fn respond_with_nonce(
    srv: &PastaServer,
    c: ClientId,
    x: [u8; X_LEN],
    req_bytes: &[u8; TOP_REQ_LEN],
    nonce: &[u8; crypto_core::NONCE_LEN],
) -> Option<ServerResponse> {
    let rec = srv.records.get(&c)?;
    let req_point = CompressedRistretto(*req_bytes).decompress()?;

    let z_i = pc::toprf_eval_share(rec.k_i, &req_point);
    let z_bytes = z_i.compress().to_bytes();

    let mut msg = [0u8; UID_LEN + X_LEN];
    msg[0..UID_LEN].copy_from_slice(&c.0);
    msg[UID_LEN..UID_LEN + X_LEN].copy_from_slice(&x);
    let y_i = pc::ttg_part_eval(&srv.ttg_share, &msg);
    let y_bytes = pc::ttg_partial_to_bytes(&y_i);

    let aad: [u8; 0] = [];
    let ctxt_i = pc::xchacha_encrypt_detached_with_nonce(&rec.h_i, &aad, &y_bytes, nonce);

    Some(ServerResponse {
        server_id: srv.id,
        z_i: z_bytes,
        ctxt_i,
    })
}

pub fn finalize(st: &ClientState, x: [u8; X_LEN], resps: &[ServerResponse]) -> Option<pc::TtgToken> {
    if resps.len() != st.t_set.len() {
        return None;
    }

    let mut ids: Vec<u32> = resps.iter().map(|r| r.server_id).collect();
    ids.sort_unstable();
    let mut t_sorted = st.t_set.clone();
    t_sorted.sort_unstable();
    if ids != t_sorted {
        return None;
    }

    let lambdas = crypto_core::lagrange_coeffs_at_zero(&t_sorted);
    let mut partials = Vec::with_capacity(resps.len());
    for &sid in &t_sorted {
        let r = resps.iter().find(|r| r.server_id == sid).unwrap();
        let pt = CompressedRistretto(r.z_i).decompress()?;
        partials.push(pt);
    }
    let h = crypto_core::toprf_client_eval_from_partials(&st.password, st.rho, &partials, &lambdas);

    let aad: [u8; 0] = [];
    let mut ttg_partials = Vec::with_capacity(resps.len());
    for &sid in &t_sorted {
        let r = resps.iter().find(|r| r.server_id == sid).unwrap();
        let h_i = pc::hash_hi(&h, sid);
        let y_bytes = pc::xchacha_decrypt_detached(&h_i, &aad, &r.ctxt_i).ok()?;
        let part = pc::ttg_token_from_partial_bytes(&y_bytes)?;
        ttg_partials.push(part);
    }

    Some(pc::ttg_combine(&t_sorted, &ttg_partials))
}

pub fn verify(vk: &pc::TtgVk, c: ClientId, x: [u8; X_LEN], tk: &pc::TtgToken) -> bool {
    let mut msg = [0u8; UID_LEN + X_LEN];
    msg[0..UID_LEN].copy_from_slice(&c.0);
    msg[UID_LEN..UID_LEN + X_LEN].copy_from_slice(&x);
    pc::ttg_verify(vk, &msg, tk)
}

// Benchmark fixtures

#[derive(Clone)]
pub struct Fixture {
    pub n: usize,
    pub t: usize,
    pub c: ClientId,
    pub x: [u8; X_LEN],
    pub password: Vec<u8>,
    pub vk: pc::TtgVk,
    pub servers: Vec<PastaServer>,
    pub t_set: Vec<u32>,
}

fn seed_for(tag: &[u8], n: usize, t: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&(n as u64).to_le_bytes());
    h.update(&(t as u64).to_le_bytes());
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(out.as_bytes());
    seed
}

pub fn make_fixture(n: usize, t: usize) -> Fixture {
    assert!(t >= 1 && t <= n);
    let mut rng = ChaCha20Rng::from_seed(seed_for(b"pasta/fixture/v1", n, t));

    let mut c_bytes = [0u8; UID_LEN];
    rng.fill_bytes(&mut c_bytes);
    let c = ClientId(c_bytes);

    let mut x = [0u8; X_LEN];
    rng.fill_bytes(&mut x);

    let password = b"correct horse battery staple".to_vec();

    let gs = global_setup(128, n, t, &mut rng);
    let mut servers: Vec<PastaServer> = gs
        .ttg_shares
        .iter()
        .map(|(sid, sh)| PastaServer::new(*sid, *sh))
        .collect();
    servers.sort_by_key(|s| s.id);

    let su = signup(n, t, &password, &mut rng);
    for msg in su.msgs.iter() {
        let idx = (msg.server_id - 1) as usize;
        servers[idx].store(c, msg);
    }

    let t_set: Vec<u32> = (1..=t as u32).collect();
    Fixture {
        n,
        t,
        c,
        x,
        password,
        vk: gs.vk,
        servers,
        t_set,
    }
}

#[derive(Clone)]
pub struct IterData {
    pub rho: RScalar,
    pub req: [u8; TOP_REQ_LEN],
    pub nonces: Vec<[u8; crypto_core::NONCE_LEN]>,
}

pub fn make_iter_data(fx: &Fixture, rng: &mut impl RngCore) -> IterData {
    let rho = crypto_core::random_scalar(rng);
    let req_point = pc::toprf_encode(&fx.password, rho);
    let req = req_point.compress().to_bytes();

    let mut nonces = vec![[0u8; crypto_core::NONCE_LEN]; fx.t];
    for n in nonces.iter_mut() {
        rng.fill_bytes(n);
    }

    IterData { rho, req, nonces }
}
