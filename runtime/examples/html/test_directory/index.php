<?php
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html>
<head>
    <title>Halmos PHP Debugger</title>
    <style>
        body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
        h2 { color: #569cd6; border-bottom: 1px solid #333; }
        .box { background: #252526; border: 1px solid #454545; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .key { color: #9cdcfe; font-weight: bold; }
        .val { color: #ce9178; }
        .highlight { background: #3e3e42; padding: 2px 5px; border-radius: 3px; color: #dcdcaa; }
    </style>
</head>
<body>

    <h2>1. Utama (Target Lo)</h2>
    <div class="box">
        <p><span class="key">PATH_INFO:</span> <span class="highlight"><?php echo $_SERVER['PATH_INFO'] ?? 'KOSONG'; ?></span></p>
        <p><span class="key">QUERY_STRING:</span> <span class="highlight"><?php echo $_SERVER['QUERY_STRING'] ?? 'KOSONG'; ?></span></p>
    </div>

    <h2>2. Detail Routing (Cek SCRIPT_FILENAME)</h2>
    <div class="box">
        <?php
        $check_keys = ['SCRIPT_FILENAME', 'SCRIPT_NAME', 'REQUEST_URI', 'DOCUMENT_ROOT'];
        foreach ($check_keys as $key) {
            echo "<p><span class='key'>$key:</span> <span class='val'>" . ($_SERVER[$key] ?? 'N/A') . "</span></p>";
        }
        ?>
    </div>

    <h2>3. Raw $_GET Data</h2>
    <div class="box">
        <pre><?php print_r($_GET); ?></pre>
    </div>

</body>
</html>