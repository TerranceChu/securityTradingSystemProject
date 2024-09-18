<?php
// 全局連接變量
$global_conn = null;
$encryption_key = 'your-encryption-key'; // 請確保這個密鑰足夠強大，且保持機密
$iv = 'your-initialization-vector'; // 初始化向量，需為 16 字節長的安全隨機字節

// 加密函數
function encryptData($data) {
    global $encryption_key, $iv;
    return openssl_encrypt($data, 'aes-256-cbc', $encryption_key, 0, $iv);
}

// 解密函數
function decryptData($data) {
    global $encryption_key, $iv;
    return openssl_decrypt($data, 'aes-256-cbc', $encryption_key, 0, $iv);
}

// 設置會話安全配置
ini_set('session.cookie_httponly', 1); // 防止 JavaScript 存取 Cookie
ini_set('session.cookie_secure', 1);    // 只允許 HTTPS 連接時傳輸 Cookie

function getConnection() {
    global $global_conn;

    // 如果尚未建立連接，則進行連接
    if ($global_conn === null) {
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "stock_trading_system";

        // 建立連接
        $global_conn = new mysqli($servername, $username, $password, $dbname);

        // 獲取當前時間和用戶IP地址，用於日誌記錄
        $timestamp = date("Y-m-d H:i:s");
        $user_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        // 檢查連接是否成功
        if ($global_conn->connect_error) {
            // 記錄錯誤到日誌文件，而不是顯示技術細節給用戶
            $error_message = "[$timestamp] [IP: $user_ip] 連接失敗: " . $global_conn->connect_error;
            error_log($error_message, 3, __DIR__ . "/error_log.txt");
            die("數據庫連接失敗，請稍後重試。");
        }

        // 設置字符集，防止數據庫字符編碼問題
        if (!$global_conn->set_charset("utf8mb4")) {
            $error_message = "[$timestamp] [IP: $user_ip] 字符集設置失敗: " . $global_conn->error;
            error_log($error_message, 3, __DIR__ . "/error_log.txt");
            die("字符集設置失敗，請稍後重試。");
        }

        // 記錄成功連接的日誌
        $success_message = "[$timestamp] [IP: $user_ip] 成功連接到數據庫";
        error_log($success_message, 3, __DIR__ . "/error_log.txt");
    }

    // 返回全局連接
    return $global_conn;
}

// 在腳本結束時自動關閉連接
register_shutdown_function(function() {
    global $global_conn;
    if ($global_conn !== null) {
        $timestamp = date("Y-m-d H:i:s");
        $user_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        error_log("[$timestamp] [IP: $user_ip] 關閉數據庫連接", 3, __DIR__ . "/error_log.txt");
        $global_conn->close();
        $global_conn = null; // 確保連接被設置為 null，防止重複關閉
    }
});
?>
