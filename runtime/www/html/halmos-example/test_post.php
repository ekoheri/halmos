<?php
    $username = $_POST['username'];
    $passwd = $_POST['passwd'];

    if( ($username == 'ekoheri@gmail.com') && ($passwd == '234')) {
        echo "<h1>Proses Login Berhasil</h1>\n";
        echo "<p>User Name anda : $username</p>\n";
    } else {
        echo "<h1>Anda Gagal Login!</h1>\n";
        echo "<p>User Name $username anda salah</p>\n";
        echo "<p>Atau password $passwd ini salah</p>\n";
    }
?>