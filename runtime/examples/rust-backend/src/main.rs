// cargo build --release
// sudo pkill halmos-rust-backend
// sudo spawn-fcgi -a 127.0.0.1 -p 9001 -n /home/eko/halmos-rust-backend/target/release/halmos-rust-backend

use fastcgi;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use std::io::Write;
use std::time::Instant;

fn mod_exp_manual(base: &BigUint, exp: &BigUint, m: &BigUint) -> BigUint {
    let mut res = BigUint::one();
    let mut base = base % m;
    let mut exp = exp.clone();

    while exp > BigUint::zero() {
        if &exp % 2u32 == BigUint::one() {
            res = (res * &base) % m;
        }
        base = (&base * &base) % m;
        exp >>= 1;
    }
    res
}

fn format_hexa(num: &BigUint) -> String {
    let s = format!("{:x}", num);
    if s.len() > 40 {
        format!("{}...{} ({} chars)", &s[..20], &s[s.len()-20..], s.len())
    } else {
        s
    }
}

fn main() {
    // RFC 3526 MODP Group 14 (2048-bit)
    let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
                 29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
                 EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
                 E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
                 EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
                 C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
                 83655D23DCA3AD961C62F356208552BB9ED529077096966D\
                 670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
                 E39E772C180E86039B2783A2EC07A28FB5C55DF06F4BB242\
                 431D3C20A9107119558B664687A69002B5E8CE4286110C9A\
                 891C2A562AD95A3C8471FA60515630A868B448F8BAD697C1\
                 572445B2F1391216957C452445447D74F74FA50462463F4B\
                 0202F1391216957C452445447D74F74FA50462463F4B0202\
                 FFFFFFFFFFFFFFFF";

    let p = BigUint::parse_bytes(p_hex.as_bytes(), 16).expect("Failed to parse P");
    let g = BigUint::from(2u32);

    fastcgi::run(move |mut req| {
        let qs = req.param("QUERY_STRING").unwrap_or_else(|| "".to_string());
        let mode_manual = qs.contains("mode=manual");

        let start = Instant::now();
        let mut rng = rand::thread_rng();

        // Generate 2048-bit Private Keys
        let a_priv = rng.gen_biguint(2048);
        let b_priv = rng.gen_biguint(2048);

        let (a_pub, b_pub, a_shared, b_shared);

        if mode_manual {
            a_pub = mod_exp_manual(&g, &a_priv, &p);
            b_pub = mod_exp_manual(&g, &b_priv, &p);
            a_shared = mod_exp_manual(&b_pub, &a_priv, &p);
            b_shared = mod_exp_manual(&a_pub, &b_priv, &p);
        } else {
            // Rust mod_pow sudah dioptimalkan (seperti gmp_powm)
            a_pub = g_powm(&g, &a_priv, &p);
            b_pub = g_powm(&g, &b_priv, &p);
            a_shared = g_powm(&b_pub, &a_priv, &p);
            b_shared = g_powm(&a_pub, &b_priv, &p);
        }

        let duration = start.elapsed();
        let is_match = a_shared == b_shared;

        let response = format!(
            "Content-Type: text/plain\r\n\r\n\
             === Halmos DHE 2048-bit Rust Test ===\n\
             Mode Used        : {}\n\
             Computation Time : {:.4} Seconds\n\
             Status           : {}\n\
             ---------------------------------------\n\
             Alice Pub : {}\n\
             Bob Pub   : {}\n\
             Shared Key: {}\n",
            if mode_manual { "MANUAL" } else { "LIBRARY (Optimized)" },
            duration.as_secs_f64(),
            if is_match { "YES! MATCH" } else { "ERROR" },
            format_hexa(&a_pub),
            format_hexa(&b_pub),
            format_hexa(&a_shared)
        );

        req.stdout().write_all(response.as_bytes()).unwrap();
    });
}

// Helper untuk library mod_pow
fn g_powm(base: &BigUint, exp: &BigUint, m: &BigUint) -> BigUint {
    base.modpow(exp, m)
}