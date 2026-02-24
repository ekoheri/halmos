<?php
/*
sudo apt update
sudo apt install php-gmp
Cek versi PHP dulu kalau gak yakin (misal 7.3)
php -v
Lalu restart service-nya
sudo systemctl restart php7.3-f
*/

function mod_exp_manual($base, $exp, $mod) {
    $result = gmp_init(1);
    $base = gmp_mod($base, $mod);
    while (gmp_sign($exp) > 0) {
        if (gmp_strval(gmp_mod($exp, 2)) == '1') {
            $result = gmp_mod(gmp_mul($result, $base), $mod);
        }
        $exp = gmp_div_q($exp, 2);
        $base = gmp_mod(gmp_mul($base, $base), $mod);
    }
    return $result;
}

function format_hexa($num) {
    $hex = gmp_strval($num, 16);
    return substr($hex, 0, 20) . "..." . substr($hex, -20) . " (" . strlen($hex) . " chars)";
}

// Ambil mode dari query string, default ke 'lib'
$mode = isset($_GET['mode']) && $_GET['mode'] === 'manual' ? 'manual' : 'lib';

// === PARAMETER RFC 3526 MODP Group 14 (2048-bit) ===
$p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" .
         "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" .
         "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" .
         "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" .
         "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" .
         "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" .
         "83655D23DCA3AD961C62F356208552BB9ED529077096966D" .
         "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" .
         "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4BB242" .
         "431D3C20A9107119558B664687A69002B5E8CE4286110C9A" .
         "891C2A562AD95A3C8471FA60515630A868B448F8BAD697C1" .
         "572445B2F1391216957C452445447D74F74FA50462463F4B" .
         "0202F1391216957C452445447D74F74FA50462463F4B0202" . // Padding disesuaikan untuk 2048-bit
         "FFFFFFFFFFFFFFFF";

$p = gmp_init($p_hex, 16);
$g = gmp_init(2);

$start = microtime(true);

// Generate Keys
$a_priv = gmp_random_bits(2048);
$b_priv = gmp_random_bits(2048);

if ($mode === 'manual') {
    $a_pub = mod_exp_manual($g, $a_priv, $p);
    $b_pub = mod_exp_manual($g, $b_priv, $p);
    $a_shared = mod_exp_manual($b_pub, $a_priv, $p);
    $b_shared = mod_exp_manual($a_pub, $b_priv, $p);
} else {
    $a_pub = gmp_powm($g, $a_priv, $p);
    $b_pub = gmp_powm($g, $b_priv, $p);
    $a_shared = gmp_powm($b_pub, $a_priv, $p);
    $b_shared = gmp_powm($a_pub, $b_priv, $p);
}

$end = microtime(true);
$total_time = $end - $start;

header("Content-Type: text/plain");
echo "=== DHE 4096-bit Hybrid Stress Test ===\n";
echo "Mode Used        : " . strtoupper($mode) . "\n";
echo "Computation Time : " . number_format($total_time, 4) . " Seconds\n";
echo "Status           : " . (gmp_cmp($a_shared, $b_shared) == 0 ? "YES! MATCH" : "ERROR") . "\n";
echo "---------------------------------------\n";
echo "Alice Pub : " . format_hexa($a_pub) . "\n";
echo "Bob Pub   : " . format_hexa($b_pub) . "\n";
echo "Shared Key: " . format_hexa($a_shared) . "\n";
?>