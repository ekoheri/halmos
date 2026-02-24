<?php

class Halmos_IPC {
    private static $socketPath = '/tmp/halmos_bridge.sock';
    // Ambil dari config: internal_prefix
    private static $prefix = "HALMOS_"; 

    public static function send($target, $event, $msg) {
        $data = [
            "header" => [
                "action" => "PRIVATE",           
                "dst"    => $target,             
                "src"    => self::$prefix . "PHP" 
            ],
            // Kita bungkus jadi array biar di Browser bisa dibedakan mana event mana isi
            "payload" => [
                "event" => $event,
                "message" => $msg
            ]
        ];

        // WAJIB tambahkan PHP_EOL atau "\n" di akhir
        $json = json_encode($data) . "\n";
        
        // Gunakan socket_create agar lebih robust untuk Unix Socket
        
        $socket = socket_create(AF_UNIX, SOCK_STREAM, 0);

        // Set timeout biar PHP gak ikutan hang kalau Halmos lagi sibuk
        socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, array('sec' => 0, 'usec' => 500000));
        
        if (!@socket_connect($socket, self::$socketPath)) {
            error_log("Halmos Error: Gagal konek ke socket.");
            return false;
        }

        socket_write($socket, $json, strlen($json));
        socket_close($socket);
        return true;
    }
}