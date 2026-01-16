// cargo build --release
// sudo pkill halmos-rust-backend
// sudo spawn-fcgi -a 127.0.0.1 -p 9001 -n /home/eko/halmos-rust-backend/target/release/halmos-rust-backend

extern crate fastcgi;
use std::io::Write;
use std::time::Instant;

fn fibonacci(n: u32) -> u32 {
    if n <= 1 { return n; }
    fibonacci(n - 1) + fibonacci(n - 2)
}

fn sieve(limit: usize) -> usize {
    let mut primes = vec![true; limit + 1];
    primes[0] = false; primes[1] = false;
    for p in 2..=((limit as f64).sqrt() as usize) {
        if primes[p] {
            let mut i = p * p;
            while i <= limit { primes[i] = false; i += p; }
        }
    }
    primes.iter().filter(|&&is_prime| is_prime).count()
}

fn mandelbrot() -> u64 {
    let (width, height, max_iter) = (800, 600, 1000);
    let mut sum = 0;
    for y in 0..height {
        for x in 0..width {
            let (mut z_re, mut z_im) = (0.0, 0.0);
            let c_re = (x as f64 - width as f64 / 1.5) * 4.0 / width as f64;
            let c_im = (y as f64 - height as f64 / 2.0) * 4.0 / height as f64;
            let mut iter = 0;
            while z_re * z_re + z_im * z_im <= 4.0 && iter < max_iter {
                let tmp = z_re * z_re - z_im * z_im + c_re;
                z_im = 2.0 * z_re * z_im + c_im;
                z_re = tmp;
                iter += 1;
            }
            sum += iter as u64;
        }
    }
    sum
}

fn main() {
    fastcgi::run(|mut request| {
        let query = request.param("QUERY_STRING").unwrap_or_default();
        
        // 1. Ambil nilai setelah "jenis="
        // Contoh: "jenis=mandelbrot" -> "mandelbrot"
        let raw_jenis = query.split('=')
                            .nth(1)
                            .unwrap_or("unknown");

        // 2. Buat huruf pertama menjadi kapital (Uppercase)
        // "mandelbrot" -> "Mandelbrot"
        let mut chars = raw_jenis.chars();
        let jenis_kapital = match chars.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
        };

        let start = Instant::now();
        let msg = if raw_jenis == "fibo" {
            format!("Fibonacci(30) = {}", fibonacci(30))
        } else if raw_jenis == "prime" {
            format!("Sieve Prima hingga 1M = {} ditemukan", sieve(1_000_000))
        } else if raw_jenis == "mandelbrot" {
            format!("Mandelbrot Checksum = {}", mandelbrot())
        } else {
            "Gunakan ?jenis=fibo, prime, atau mandelbrot".to_string()
        };

        let duration = start.elapsed();
        let response = format!(
            "Content-Type: text/html\r\n\r\n\
            <h1>Rust Stress Test: {}</h1>\
            <p><strong>Hasil:</strong> {}</p>\
            <p><strong>Waktu Eksekusi:</strong> {:.6} detik</p>",
            jenis_kapital, msg, duration.as_secs_f64()
        );

        // Ganti bagian akhir yang mengirim response menjadi seperti ini:
        match request.stdout().write_all(response.as_bytes()) {
            Ok(_) => (),
            Err(e) => eprintln!("Rust Write Error: {}", e), // Ini akan muncul di terminal tempat spawn-fcgi jalan
        }
    });
}
