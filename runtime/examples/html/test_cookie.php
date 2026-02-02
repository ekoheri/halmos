<?php
if(!isset($_COOKIE['halmos_test'])) {
    setcookie('halmos_test', 'Halmos-v1.3-Ganteng', time() + 3600);
    echo "Cookie belum ada, baru dipasang. Refresh deh!";
} else {
    echo "Cookie ketemu! Isinya: " . $_COOKIE['halmos_test'];
}