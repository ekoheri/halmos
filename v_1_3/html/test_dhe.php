<?php
/*
sudo apt update
sudo apt install php-gmp
Cek versi PHP dulu kalau gak yakin (misal 8.1 atau 8.2)
php -v
Lalu restart service-nya
sudo systemctl restart php8.x-f
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

// Parameter RFC 3526 MODP Group 16 (4096-bit)
$p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" .
         "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" .
         "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" .
         "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" .
         "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" .
         "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" .
         "83655D23DCA3AD961C62F356208552BB9ED529077096966D" .
         "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" .
         "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" .
         "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" .
         "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" .
         "ECFB850458DBEF0A8AEA7157FF9AF678F5397FC264333684" .
         "725248B0A31352101F0264110284593B01168B5C55DF06F4" .
         "C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA" .
         "051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

$p = gmp_init($p_hex, 16);
$g = gmp_init(2);

$start = microtime(true);

// Generate Keys
$a_priv = gmp_random_bits(4096);
$b_priv = gmp_random_bits(4096);

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