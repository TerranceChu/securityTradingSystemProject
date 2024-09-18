<?php
include 'db.php';

session_start();

if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

// 如果尚未生成 CSRF Token，生成一個
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = ''; // 初始化錯誤消息變數

try {
    $conn = getConnection(); // 獲取全局數據庫連接

    if ($_SERVER["REQUEST_METHOD"] == "POST") {

        // 1. 檢查 CSRF Token
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $error = "CSRF Token 驗證失敗";
        }

        // 2. 驗證股票代碼
        elseif (!preg_match("/^[A-Z]{1,5}$/", $_POST['stock_symbol'])) {
            $error = "無效的股票代碼";
        }

        // 3. 驗證數量
        elseif (!is_numeric($_POST['quantity']) || $_POST['quantity'] <= 0 || intval($_POST['quantity']) != $_POST['quantity']) {
            $error = "無效的數量，必須是正整數";
        }

        // 4. 驗證交易類型
        elseif (!in_array($_POST['trade_type'], ['buy', 'sell'])) {
            $error = "無效的交易類型";
        }

        if (empty($error)) {
            // 查詢用戶的 ID
            $username = $_SESSION['username'];
            $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $row = $result->fetch_assoc();
                $user_id = $row['id'];

                // 將股票代碼轉換為大寫並修整
                $stock_symbol = strtoupper(trim($_POST['stock_symbol']));
                $quantity = intval($_POST['quantity']); // 將數量轉為整數
                
                // 調試數量，確保數量在加密之前正確
                echo "原始數量（加密前）: " . $quantity . "<br>";

                $trade_type = $_POST['trade_type'];

                // 處理賣出操作前的股票數量驗證
                if ($trade_type === 'sell') {
                    // 查詢持有的股票數量
                    $stmt = $conn->prepare("SELECT quantity FROM user_stocks WHERE user_id = ? AND stock_symbol = ?");
                    $stmt->bind_param("is", $user_id, $stock_symbol);
                    $stmt->execute();
                    $result = $stmt->get_result();
                    $row = $result->fetch_assoc();

                    $current_quantity = $row['quantity'] ?? 0;

                    if ($current_quantity < $quantity) {
                        $error = "賣出失敗：持有股票數量不足";
                    }
                }

                if (empty($error)) {
                    // 加密股票代碼和數量
                    $encrypted_symbol = encryptData($stock_symbol);
                    $quantity = intval($_POST['quantity']); // 不加密，保持數字

                    // 插入交易記錄
                    $stmt = $conn->prepare("INSERT INTO trades (user_id, stock_symbol, quantity, trade_type) VALUES (?, ?, ?, ?)");
                    $stmt->bind_param("ssis", $user_id, $encrypted_symbol, $quantity, $trade_type);

                    if ($stmt->execute()) {
                        // 根據交易類型更新 user_stocks 表
                        if ($trade_type === 'buy') {
                            $stmt = $conn->prepare("INSERT INTO user_stocks (user_id, stock_symbol, quantity) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE quantity = quantity + ?");
                            $stmt->bind_param("issi", $user_id, $encrypted_symbol, $quantity, $quantity);
                        } else if ($trade_type === 'sell') {
                            $stmt = $conn->prepare("UPDATE user_stocks SET quantity = quantity - ? WHERE user_id = ? AND stock_symbol = ?");
                            $stmt->bind_param("iis", $quantity, $user_id, $stock_symbol);
                        }

                        if ($stmt->execute()) {
                            // 交易成功後重新生成 CSRF Token
                            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

                            // 清除表單數據
                            $_POST['stock_symbol'] = '';
                            $_POST['quantity'] = '';
                            $_POST['trade_type'] = 'buy'; // 默認選擇 "buy"

                            // 記錄成功交易
                            error_log("用戶 $username 成功進行了一次交易: $trade_type $quantity $stock_symbol");

                            // 重定向，防止重複提交
                            header("Location: trade.php?success=true");
                            exit;
                        } else {
                            $error = "更新持股記錄時出錯: " . $stmt->error;
                        }
                    } else {
                        $error = "交易過程中發生錯誤: " . $stmt->error;
                    }
                }

                $stmt->close();
            } else {
                $error = "用戶不存在，請重新登錄";
            }
        }

    }
} catch (Exception $e) {
    $error = "系統錯誤: " . $e->getMessage();
    error_log("交易系統錯誤: " . $e->getMessage());
}
?>
<nav style="background-color: #333; padding: 10px; color: white;">
    <a href="dashboard.php" style="color: white; margin-right: 20px; text-decoration: none;">交易歷史記錄</a>
    <a href="trade.php" style="color: white; margin-right: 20px; text-decoration: none;">進行交易</a>
    <a href="logout.php" style="color: white; text-decoration: none;">登出</a>
</nav>

<!-- 股票代碼表格 -->
<h2>可用股票代碼</h2>
<table border="1" cellpadding="10" cellspacing="0" style="width: 100%; text-align: center;">
    <tr>
        <th>熱門股票名稱</th>
        <th>股票代碼</th>
    </tr>
    <tr>
        <td>Apple</td>
        <td>AAPL</td>
    </tr>
    <tr>
        <td>Google</td>
        <td>GOOGL</td>
    </tr>
    <tr>
        <td>Amazon</td>
        <td>AMZN</td>
    </tr>
    <tr>
        <td>Microsoft</td>
        <td>MSFT</td>
    </tr>
    <tr>
        <td>Tesla</td>
        <td>TSLA</td>
    </tr>
</table>

<!-- 交易表單 -->
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    股票代碼: <input type="text" name="stock_symbol" value="<?php echo htmlspecialchars($_POST['stock_symbol'] ?? '', ENT_QUOTES); ?>" required><br>
    數量: <input type="number" name="quantity" value="<?php echo htmlspecialchars($_POST['quantity'] ?? '', ENT_QUOTES); ?>" required><br>
    買賣: <select name="trade_type">
        <option value="buy" <?php echo ($_POST['trade_type'] ?? '') == 'buy' ? 'selected' : ''; ?>>買入</option>
        <option value="sell" <?php echo ($_POST['trade_type'] ?? '') == 'sell' ? 'selected' : ''; ?>>賣出</option>
    </select><br>
    <button type="submit">提交交易</button>
</form>

<?php if (!empty($error)): ?>
    <div style="color: red; border: 1px solid red; padding: 5px;">
        <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
    </div>
<?php endif; ?>

<?php if (isset($_GET['success']) && $_GET['success'] == 'true'): ?>
    <div style="color: green; border: 1px solid green; padding: 5px;">
        交易已成功提交。
    </div>
<?php endif; ?>
