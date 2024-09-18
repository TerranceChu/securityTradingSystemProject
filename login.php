<?php
include 'db.php';

session_start();

$error = ''; // 初始化錯誤消息變數
$login_block_time = 300; // 設置5分鐘的鎖定時間

// 初始化 CSRF Token（如果不存在）
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// 初始化登錄失敗次數和時間（如果不存在）
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['last_attempt_time'] = time();
}

// 檢查是否超過5次錯誤登錄並設置時間限制
if ($_SESSION['login_attempts'] >= 5) {
    $time_diff = time() - $_SESSION['last_attempt_time'];
    if ($time_diff < $login_block_time) {
        $remaining_time = $login_block_time - $time_diff;
        $error = "登錄失敗次數過多，請稍後再試。剩餘時間: " . ceil($remaining_time / 60) . " 分鐘";
        // 記錄日誌，顯示登錄失敗次數過多
        error_log("[" . date("Y-m-d H:i:s") . "] IP: {$_SERVER['REMOTE_ADDR']} 用戶 $username 登錄失敗次數過多，鎖定剩餘時間: " . ceil($remaining_time / 60) . " 分鐘");
    } else {
        // 如果過了鎖定時間，重置嘗試次數
        $_SESSION['login_attempts'] = 0;
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && empty($error)) {
    // 檢查 CSRF Token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "CSRF Token 驗證失敗";
        error_log("[" . date("Y-m-d H:i:s") . "] IP: {$_SERVER['REMOTE_ADDR']} CSRF Token 驗證失敗");
    } else {
        // 清理輸入
        $username = trim($_POST['username']);
        $password = trim($_POST['password']);

        // 檢查是否輸入了用戶名和密碼
        if (empty($username) || empty($password)) {
            $error = "請輸入用戶名和密碼";
        } else {
            // 使用 prepared statement 防止 SQL 注入
            $conn = getConnection(); // 獲取數據庫連接
            $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $row = $result->fetch_assoc();
                // 驗證密碼
                if (password_verify($password, $row['password'])) {
                    // 防止會話固定攻擊
                    session_regenerate_id(true);
                    $_SESSION['username'] = $username;
                    $_SESSION['role'] = $row['role'];

                    // 重置登錄嘗試次數
                    $_SESSION['login_attempts'] = 0;
                    $_SESSION['last_attempt_time'] = time();

                    // 記錄成功登錄的日誌
                    error_log("[" . date("Y-m-d H:i:s") . "] IP: {$_SERVER['REMOTE_ADDR']} 用戶 $username 登錄成功");

                    // 重定向到儀表板
                    header("Location: dashboard.php");
                    exit;
                } else {
                    $error = "密碼錯誤，請重試";
                    $_SESSION['login_attempts']++; // 增加登錄失敗次數
                    $_SESSION['last_attempt_time'] = time(); // 設置最後一次嘗試的時間
                    // 記錄錯誤的日誌
                    error_log("[" . date("Y-m-d H:i:s") . "] IP: {$_SERVER['REMOTE_ADDR']} 用戶 $username 密碼錯誤");
                }
            } else {
                $error = "用戶名不存在";
                // 記錄用戶不存在的日誌
                error_log("[" . date("Y-m-d H:i:s") . "] IP: {$_SERVER['REMOTE_ADDR']} 嘗試的用戶名 $username 不存在");
            }

            $stmt->close();
        }
    }
}
?>

<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    
    <label for="username">用戶名:</label>
    <input type="text" name="username" id="username" required><br>

    <label for="password">密碼:</label>
    <input type="password" name="password" id="password" required><br>

    <button type="submit">登入</button>
</form>

<?php if (!empty($error)): ?>
    <div style="color: red; border: 1px solid red; padding: 5px;">
        <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?> <!-- 防止XSS攻擊 -->
    </div>
<?php endif; ?>

<!-- 註冊按鈕 -->
<div style="margin-top: 20px;">
    <p>還沒有帳戶嗎？ <a href="register.php">點此註冊</a></p>
</div>
