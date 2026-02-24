# python3.10 -m pip install flup
# python3.10 app.py

import time
import binascii
from flup.server.fcgi import WSGIServer

# RFC 3526 MODP Group 14 (2048-bit)
P_HEX = ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
         "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
         "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
         "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
         "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
         "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
         "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
         "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
         "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4BB242"
         "431D3C20A9107119558B664687A69002B5E8CE4286110C9A"
         "891C2A562AD95A3C8471FA60515630A868B448F8BAD697C1"
         "572445B2F1391216957C452445447D74F74FA50462463F4B"
         "0202F1391216957C452445447D74F74FA50462463F4B0202"
         "FFFFFFFFFFFFFFFF")

P = int(P_HEX, 16)
G = 2

def mod_exp_manual(base, exp, mod):
    res = 1
    base %= mod
    while exp > 0:
        if exp % 2 == 1:
            res = (res * base) % mod
        base = (base * base) % mod
        exp //= 2
    return res

def format_hexa(num):
    h = hex(num)[2:] # Buang '0x'
    if len(h) > 40:
        return f"{h[:20]}...{h[-20:]} ({len(h)} chars)"
    return h

def app(environ, start_response):
    query_string = environ.get('QUERY_STRING', '')
    mode_manual = 'mode=manual' in query_string

    import secrets # Lebih aman untuk crypto dibanding random standar
    
    start_time = time.time()
    
    # Generate 2048-bit Private Keys
    a_priv = secrets.randbits(2048)
    b_priv = secrets.randbits(2048)

    if mode_manual:
        a_pub = mod_exp_manual(G, a_priv, P)
        b_pub = mod_exp_manual(G, b_priv, P)
        a_shared = mod_exp_manual(b_pub, a_priv, P)
        b_shared = mod_exp_manual(a_pub, b_priv, P)
    else:
        # Python pow(a, b, m) sudah pakai modular exponentiation yang sangat cepat (C-optimized)
        a_pub = pow(G, a_priv, P)
        b_pub = pow(G, b_priv, P)
        a_shared = pow(b_pub, a_priv, P)
        b_shared = pow(a_pub, b_priv, P)

    end_time = time.time()
    duration = end_time - start_time
    is_match = (a_shared == b_shared)

    response_body = (
        f"=== Halmos DHE 2048-bit Python (Flup) ===\n"
        f"Mode Used        : {'MANUAL' if mode_manual else 'POW() OPTIMIZED'}\n"
        f"Computation Time : {duration:.4f} Seconds\n"
        f"Status           : {'YES! MATCH' if is_match else 'ERROR'}\n"
        f"---------------------------------------\n"
        f"Alice Pub : {format_hexa(a_pub)}\n"
        f"Bob Pub   : {format_hexa(b_pub)}\n"
        f"Shared Key: {format_hexa(a_shared)}\n"
    )

    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [response_body.encode('utf-8')]

if __name__ == '__main__':
    # Halmos akan menembak ke port 9002
    WSGIServer(app, bindAddress=('127.0.0.1', 9002)).run()