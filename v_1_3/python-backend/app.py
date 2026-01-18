import time

# 1. Fibonacci (Recursive - CPU Stack Test)
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)

# 2. Prime Sieve (Memory & Loop Test)
def sieve(limit):
    primes = [True] * (limit + 1)
    primes[0] = primes[1] = False
    for p in range(2, int(limit**0.5) + 1):
        if primes[p]:
            for i in range(p * p, limit + 1, p):
                primes[i] = False
    return len([p for p in primes if p])

# 3. Mandelbrot (Floating Point Test)
def mandelbrot(width, height, max_iter):
    total_sum = 0
    for y in range(height):
        for x in range(width):
            z_re = 0.0
            z_im = 0.0
            c_re = (x - width / 1.5) * 4.0 / width
            c_im = (y - height / 2.0) * 4.0 / height
            
            iteration = 0
            while z_re*z_re + z_im*z_im <= 4.0 and iteration < max_iter:
                tmp = z_re*z_re - z_im*z_im + c_re
                z_im = 2.0 * z_re * z_im + c_im
                z_re = tmp
                iteration += 1
            total_sum += iteration
    return total_sum

def app(environ, start_response):
    # Parsing Query String
    from urllib.parse import parse_qs
    query = parse_qs(environ.get('QUERY_STRING', ''))
    jenis = query.get('jenis', ['info'])[0]
    
    start_time = time.time()
    result_msg = ""
    
    if jenis == 'fibo':
        n = 30
        res = fibonacci(n)
        result_msg = f"Fibonacci({n}) = {res}"
    elif jenis == 'prime':
        limit = 1000000
        res = sieve(limit)
        result_msg = f"Sieve Prima hingga {limit} = {res} ditemukan"
    elif jenis == 'mandelbrot':
        res = mandelbrot(400, 300, 500) # Ukuran dikurangi sedikit biar gak timeout
        result_msg = f"Mandelbrot Checksum = {res}"
    else:
        status = '200 OK'
        headers = [('Content-Type', 'text/html; charset=utf-8')]
        start_response(status, headers)
        return [b"<h1>Halmos Stress Test (Python)</h1><p>Gunakan: ?jenis=fibo, prime, mandelbrot</p>"]

    end_time = time.time()
    duration = round(end_time - start_time, 6)
    
    html = f"""
    <html>
        <body>
            <h1>Python Stress Test: {jenis.capitalize()}</h1>
            <p><strong>Hasil:</strong> {result_msg}</p>
            <p><strong>Waktu Eksekusi:</strong> {duration} detik</p>
        </body>
    </html>
    """
    
    status = '200 OK'
    headers = [
        ('Content-Type', 'text/html; charset=utf-8'),
        ('Content-Length', str(len(html)))
    ]
    start_response(status, headers)
    return [html.encode('utf-8')]