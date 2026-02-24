<?php
echo "<h1>Halmos Engine Test Lab</h1>";
echo "IP Kamu: " . $_SERVER['REMOTE_ADDR'] . "<br>";
echo "Method: " . $_SERVER['REQUEST_METHOD'] . "<br>";

if ($_POST) {
    echo "<h3>Data POST masuk:</h3>";
    print_r($_POST);
}

if ($_FILES) {
    echo "<h3>File Upload masuk:</h3>";
    print_r($_FILES);
}
?>
<form method="POST" enctype="multipart/form-data">
    <input type="text" name="pesan" placeholder="Tes teks">
    <input type="file" name="berkas">
    <button type="submit">Hajar!</button>
</form>