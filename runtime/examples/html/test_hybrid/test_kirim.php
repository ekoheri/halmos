<?php
$socketPath = '/tmp/halmos_bridge.sock';

$data = [
    "header" => [
        "type" => "PRIVATE", // Ini 'action' di C, tapi 'type' di JSON
        "dst"  => "Eko",     // Ini 'to' di C, tapi 'dst' di JSON
        "src"  => "HALMOS_BACKEND" // Ini 'from' di C, tapi 'src' di JSON
    ],
    "payload" => "Halo Eko! Akhirnya kodenya nyambung setelah kamusnya bener."
];

$socket = socket_create(AF_UNIX, SOCK_STREAM, 0);
if (@socket_connect($socket, $socketPath)) {
    socket_write($socket, json_encode($data));
    echo "Pesan dikirim dengan kamus yang bener!\n";
} else {
    echo "Gagal konek! Pastikan Halmos jalan dan socket bisa diakses.\n";
}
socket_close($socket);
?>