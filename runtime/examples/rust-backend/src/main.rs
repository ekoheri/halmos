// cargo build --release
// sudo pkill halmos-rust-backend
// sudo spawn-fcgi -a 127.0.0.1 -p 9001 -n /home/eko/halmos-rust-backend/target/release/halmos-rust-backend

extern crate fastcgi;
use std::io::{Read, Write};
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
        let method = request.param("REQUEST_METHOD").unwrap_or_default();
        let content_type = request.param("CONTENT_TYPE").unwrap_or_default();
        
        let jenis = query.split('&')
            .find(|s| s.starts_with("jenis="))
            .map(|s| s.split('=').nth(1).unwrap_or(""))
            .unwrap_or("");

        let start = Instant::now();

        // --- MATCH SEBAGAI EXPRESSION (Menghilangkan Warning) ---
        let html_output = match jenis {
            "fibo" => {
                format!("<h3>Hasil Fibonacci(30): {}</h3>", fibonacci(30))
            }
            "prime" => {
                format!("<h3>Hasil Sieve Prime 1M: {} ditemukan</h3>", sieve(1_000_000))
            }
            "mandelbrot" => {
                format!("<h3>Hasil Mandelbrot Checksum: {}</h3>", mandelbrot())
            }
            "upload" => {
                use multipart::server::Multipart;
                use std::io::Cursor;
            
                // 1. Ambil boundary dari header CONTENT_TYPE
                // Bentuknya: multipart/form-data; boundary=------------------------be8dc4b...
                let boundary = content_type
                    .split("boundary=")
                    .nth(1)
                    .unwrap_or("");
            
                if boundary.is_empty() {
                    "<h3>Error: Boundary tidak ditemukan!</h3>".to_string()
                } else {
                    // Sedot seluruh body dari STDIN (Streaming yang dikirim Halmos C)
                    let mut body = Vec::new();
                    let _ = request.stdin().read_to_end(&mut body);
                    let body_size = body.len();
                    
                    let mut response_text = format!("<h3>Hasil Parsing Halmos (Rust):</h3><ul>");
                    
                    // 2. Inisialisasi Multipart Parser dengan Cursor
                    let mut mp = Multipart::with_body(Cursor::new(body), boundary);
                    
                    // 3. Iterasi setiap field (file atau teks)
                    while let Ok(Some(mut field)) = mp.read_entry() {
                        let field_name = field.headers.name.to_string();
                        
                        if let Some(filename) = field.headers.filename {
                            let mut file_data = Vec::new();
                            let _ = field.data.read_to_end(&mut file_data);
                            
                            // Tentukan folder simpan (pastikan foldernya sudah ada!)
                            let upload_path = format!("./uploads/{}", filename);
                            
                            // Simpan file ke disk
                            match std::fs::write(&upload_path, &file_data) {
                                Ok(_) => {
                                    response_text.push_str(&format!(
                                        "<li><b>FILE SAVED:</b> {} ({} bytes) -> Saved to {}</li><br>",
                                        filename, file_data.len(), upload_path
                                    ));
                                },
                                Err(e) => {
                                    response_text.push_str(&format!(
                                        "<li><b>FILE ERROR:</b> Gagal simpan {} ({})</li><br>",
                                        filename, e
                                    ));
                                }
                            }
                        } else {
                            // Jika ini adalah TEXT FIELD biasa
                            let mut text_value = String::new();
                            let _ = field.data.read_to_string(&mut text_value);
                            
                            response_text.push_str(&format!(
                                "<li><b>FIELD DETECTED:</b> {} = {}</li>",
                                field_name, text_value
                            ));
                        }
                    }
                    
                    response_text.push_str("</ul>");
                    response_text.push_str(&format!("<p>Total Raw Body: {} bytes</p>", body_size));
                    response_text
                }
            }
            _ => {
                "<h3>Menu Utama Backend Rust</h3>\
                 <p>Pilih menu: <a href='?jenis=fibo'>Fibonacci</a> | \
                 <a href='?jenis=prime'>Sieve Prime</a> | \
                 <a href='?jenis=mandelbrot'>Mandelbrot</a> | \
                 <a href='?jenis=upload'>Test Upload</a></p>".to_string()
            }
        };

        let duration = start.elapsed();
        let response = format!(
            "Content-Type: text/html\r\n\r\n\
            <html><head><title>Halmos Rust</title></head><body>\
            <h1>Halmos Worker (Rust Edition)</h1>\
            <p>Method: {} | URI: {}</p>\
            <hr>\
            {}\
            <hr>\
            <p>Waktu Eksekusi: {:.6} detik</p>\
            </body></html>",
            method, request.param("REQUEST_URI").unwrap_or_default(), html_output, duration.as_secs_f64()
        );

        let _ = request.stdout().write_all(response.as_bytes());
    });
}