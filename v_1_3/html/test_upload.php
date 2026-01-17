<?php
echo "--- DEBUG HALMOS ---\n";
echo "Metode: " . $_SERVER['REQUEST_METHOD'] . "\n";
echo "Content-Type: " . $_SERVER['CONTENT_TYPE'] . "\n";

echo "\n--- DATA POST ---\n";
print_r($_POST);

echo "\n--- DATA FILES (UPLOAD) ---\n";
print_r($_FILES);
?>