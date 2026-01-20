<?php
session_start();

// Ganti semua redirect ke file yang sedang berjalan
$current_file = basename(__FILE__); 

if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header("Location: $current_file");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['passwd'] ?? '';

    if ($username === 'admin' && $password === '12345') {
        $_SESSION['user'] = $username;
        $_SESSION['login_time'] = date("H:i:s");
        
        // Redirect balik ke diri sendiri
        header("Location: $current_file");
        exit;
    } else {
        // DEBUG: Uncomment baris di bawah kalau masih gagal terus buat liat apa yang diterima PHP
        // die("Data masuk: " . $username . " | " . $password);
        $error = "Username atau Password salah!";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Halmos Session Login</title>
    <style>
        body { font-family: sans-serif; padding: 20px; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>

    <?php if (isset($_SESSION['user'])): ?>
        <div class="success">
            <h1>Halo, <?php echo htmlspecialchars($_SESSION['user']); ?>!</h1>
            <p>Kamu login pada jam: <?php echo $_SESSION['login_time']; ?></p>
            <p><a href="test_login.php?action=logout">Logout dari Halmos</a></p>
        </div>

    <?php else: ?>
        <h1>LOGIN FORM (Halmos Engine)</h1>
        
        <?php if (isset($error)): ?>
            <p class="error"><?php echo $error; ?></p>
        <?php endif; ?>

        <form method="post" action="test_login.php">
            <p>
                <input type="text" id="id_usernama" name="username" required />
                <label for="id_usernama">Username</label>
            </p>
            <p>
                <input type="password" id="id_passwd" name="passwd" required />
                <label for="id_passwd">Password</label>
            </p>
            <input type="submit" value="Login" />
        </form>
        <p><small>Hint: admin / 12345</small></p>
    <?php endif; ?>

</body>
</html>