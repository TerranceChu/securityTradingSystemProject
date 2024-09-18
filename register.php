<?php
include 'db.php';

session_start();


// 初始化錯誤變數
$error = '';

// 如果 CSRF Token 不存在，生成一個新的
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // 初始化 $username 和 $password 變數
    $username = isset($_POST['username']) ? trim($_POST['username']) : ''; 
    $password = isset($_POST['password']) ? trim($_POST['password']) : '';

    // 檢查 CSRF Token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "CSRF Token 驗證失敗";
    } else {
        // 檢查用戶名和密碼
        if (empty($username) || empty($password)) {
            $error = "用戶名和密碼均為必填";
        }
        // 密碼強度檢查
        elseif (strlen($password) < 8 || !preg_match("/[A-Z]/", $password) || !preg_match("/[0-9]/", $password)) {
            $error = "密碼至少需包含8個字符、一個大寫字母和一個數字";
        } else {
            // 檢查用戶名是否已經存在
            $conn = getConnection(); // 獲取資料庫連接
            $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $error = "用戶名已存在，請選擇其他用戶名";
                error_log("嘗試使用已存在的用戶名 $username，時間: " . date("Y-m-d H:i:s") . "，IP: " . $_SERVER['REMOTE_ADDR']);
            } else {
                // 如果用戶名不存在，插入新用戶
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $role = "user"; // 默認角色

                $stmt = $conn->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
                $stmt->bind_param("sss", $username, $hashed_password, $role);

                if ($stmt->execute()) {
                    // 註冊成功，記錄日誌並重定向到登錄頁面
                    error_log("新用戶註冊成功: $username，時間: " . date("Y-m-d H:i:s") . "，IP: " . $_SERVER['REMOTE_ADDR']);
                    
                    // 防止會話固定攻擊
                    session_regenerate_id(true);
                    
                    // 重定向到登錄頁面
                    header("Location: login.php");
                    exit;
                } else {
                    $error = "註冊過程中出錯: " . $stmt->error;
                    error_log("註冊過程中發生錯誤: " . $stmt->error);
                }
            }

            $stmt->close();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="zh-HK">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>註冊</title>
    <style>
        /* 簡單的表單樣式 */
        form {
            margin: 20px;
        }
        label, input, button {
            display: block;
            margin: 10px 0;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px;
            border: none;
            border-radius: 5px;
        }
        button:hover {
            background-color: #45a049;
        }
        .error {
            color: red;
            border: 1px solid red;
            padding: 5px;
        }
        .login-btn {
            background-color: #008CBA;
            color: white;
            text-decoration: none;
            padding: 10px;
            border-radius: 5px;
            display: inline-block;
        }
        .login-btn:hover {
            background-color: #007B9E;
        }
    </style>
    <script>
        // 密碼強度檢查
        function validatePassword() {
            const password = document.getElementById("password").value;
            const strengthText = document.getElementById("strengthText");

            const hasUppercase = /[A-Z]/.test(password);
            const hasNumber = /\d/.test(password);
            const hasMinLength = password.length >= 8;

            if (hasUppercase && hasNumber && hasMinLength) {
                strengthText.textContent = "密碼強度：強";
                strengthText.style.color = "green";
            } else {
                strengthText.textContent = "密碼至少需包含8個字符、一個大寫字母和一個數字";
                strengthText.style.color = "red";
            }
        }
    </script>
</head>
<body>

<h1>註冊新帳戶</h1>

<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    
    <label for="username">用戶名:</label>
    <input type="text" name="username" pattern="[A-Za-z0-9]{5,}" title="用戶名必須至少包含5個字母或數字" required><br>
    
    <label for="password">密碼:</label>
    <input type="password" id="password" name="password" oninput="validatePassword()" required>
    <small id="strengthText" style="color: red;">密碼至少需包含8個字符、一個大寫字母和一個數字</small><br>
    
    <button type="submit">註冊</button>
</form>

<?php if (!empty($error)): ?>
    <div class="error">
        <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?> <!-- 防止XSS攻擊 -->
    </div>
<?php endif; ?>

<!-- 登入按鈕 -->
<a href="login.php" class="login-btn">已有帳號？點此登入</a>

</body>
</html>
