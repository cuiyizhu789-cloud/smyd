<?php
/**
 * 小米运动(Zepp Life)刷步数引擎 - Zepp API 版(纯 API, 去网页)
 *
 * 接口用法(GET / POST 均可):
 *   GET  ?user=账号&pwd=密码&step=28000&token=666
 *   POST user=账号&pwd=密码&step=28000&token=666   (推荐, 密码不进 URL)
 *   step 支持数字(1~98800)或"随机数"(自动生成 18000~30000 随机步数)
 *
 * 作者: 传康KK
 */

// ==================== 配置区(只改这里) ====================
// API 密钥: 默认 666, 可通过环境变量 STEP_TOKEN 覆盖
$token = trim(getenv('STEP_TOKEN')) ?: "666";

// 限频: 每分钟每 IP 最多请求次数(0 = 不限频)
$RATE_LIMIT_MAX = 0;

// 缓存目录: 默认当前目录下 cache, 可通过环境变量 STEP_CACHE_DIR 覆盖
$CACHE_DIR = getenv('STEP_CACHE_DIR') ?: __DIR__ . '/cache';

// 是否信任反向代理(部署在可信反向代理后时设 true, 限频读取 X-Forwarded-For 首个 IP)
$TRUST_PROXY = getenv('STEP_TRUST_PROXY') === '1';

// 时区
date_default_timezone_set('Asia/Shanghai');
// =======================================================

// 统一 JSON 输出(带正确状态码与禁止缓存头)
function jsonResponse($data, $code = 200) {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($json === false) {
        $json = json_encode(['error' => '响应编码失败'], JSON_UNESCAPED_UNICODE);
    }
    echo $json;
    exit;
}

// 缓存目录
function cacheBaseDir() {
    global $CACHE_DIR;
    return $CACHE_DIR;
}

// 同源校验: 判断请求是否来自本站页面(用于放行网页表单 POST, 阻止跨站伪造)
function isSameOrigin() {
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $origin = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? '';
    if ($host === '' || $origin === '') return false;
    $parts = parse_url($origin);
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) return false;
    $scheme = strtolower($parts['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') return false;
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');
    $originPort = isset($parts['port']) ? (int)$parts['port'] : ($scheme === 'https' ? 443 : 80);
    $reqHost = strtolower(preg_replace('/[^a-zA-Z0-9.\-:\[\]]/', '', $host));
    $reqPort = $isHttps ? 443 : 80;
    if (preg_match('#^(.*):(\d+)$#', $reqHost, $m)) {
        $reqHost = $m[1];
        $reqPort = (int)$m[2];
    }
    return $reqHost === strtolower($parts['host']) && $reqPort === $originPort;
}

function param($key, $default = '') {
    $v = $_POST[$key] ?? $_GET[$key] ?? $default;
    return is_string($v) ? trim($v) : $default;
}

// 脱敏账号
function desensitizeUserName($user) {
    $len = strlen($user);
    if ($len <= 8) {
        $ln = max(intval(floor($len / 3)), 1);
        return substr($user, 0, $ln) . "***" . substr($user, -$ln);
    }
    return substr($user, 0, 3) . "****" . substr($user, -4);
}

// 安全文件名过滤
function getSafeFilename($username) {
    $safeName = preg_replace('/[^a-zA-Z0-9_\-@.]/', '_', $username);
    if (strlen($safeName) > 100) $safeName = substr($safeName, 0, 100);
    return $safeName;
}

// 步数解析
function resolveStep($step) {
    $step = trim($step);
    if ($step === '' || in_array(strtolower($step), ['随机数', '随机', 'random', 'rand', '?'], true)) {
        return [true, mt_rand(18000, 30000), true];
    }
    if (!preg_match('/^\d+$/', $step)) {
        return [false, 'step 参数必须是整数或"随机数"', false];
    }
    $step = intval($step);
    if ($step < 1) return [false, '步数不能小于1', false];
    if ($step > 98800) return [false, '步数不能超过98800(每日最大合理步数)', false];
    return [true, $step, false];
}

// 频率限制(基于IP, 次数由顶部 $RATE_LIMIT_MAX 控制)
function checkRateLimit() {
    global $TRUST_PROXY, $RATE_LIMIT_MAX;
    if ($RATE_LIMIT_MAX <= 0) return [true, ''];

    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if ($TRUST_PROXY && isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $xff = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $first = trim($xff[0]);
        if ($first !== '') $ip = $first;
    }
    $rateLimitDir = cacheBaseDir() . '/rate_limit/';
    if (!is_dir($rateLimitDir)) @mkdir($rateLimitDir, 0755, true);
    if (!is_dir($rateLimitDir) || !is_writable($rateLimitDir)) return [true, ''];

    if (mt_rand(1, 20) === 1) {
        $files = glob($rateLimitDir . '*.txt*');
        if (is_array($files) && count($files) > 200) {
            usort($files, function ($a, $b) { return @filemtime($a) - @filemtime($b); });
            $removeCount = (int)(count($files) / 2);
            for ($i = 0; $i < $removeCount; $i++) @unlink($files[$i]);
        }
    }

    $rateLimitFile = $rateLimitDir . md5($ip) . '.txt';
    $currentTime = time();
    $windowSize = 60;

    $lockFp = @fopen($rateLimitDir . '.lock', 'c');
    if (!$lockFp) return [true, ''];

    $ok = true; $msg = '';
    if (flock($lockFp, LOCK_EX)) {
        $requests = [];
        if (file_exists($rateLimitFile)) {
            $data = @file_get_contents($rateLimitFile);
            $requests = json_decode((string)$data, true);
            if (!is_array($requests)) $requests = [];
        }
        $requests = array_values(array_filter($requests, function ($timestamp) use ($currentTime, $windowSize) {
            return is_numeric($timestamp) && ($currentTime - $timestamp) < $windowSize;
        }));
        if (count($requests) >= $RATE_LIMIT_MAX) {
            $ok = false;
            $msg = '请求过于频繁, 请稍后再试(每分钟最多' . $RATE_LIMIT_MAX . '次)';
        } else {
            $requests[] = $currentTime;
            $tmp = $rateLimitFile . '.tmp.' . uniqid('', true);
            if (@file_put_contents($tmp, json_encode(array_values($requests))) !== false) {
                @rename($tmp, $rateLimitFile);
                @chmod($rateLimitFile, 0600);
            }
        }
        flock($lockFp, LOCK_UN);
    }
    fclose($lockFp);
    return [$ok, $msg];
}

// ==================== 核心: MiMotionRunner ====================
class MiMotionRunner {
    private $user;
    private $password;
    public $logStr = "";
    public $invalid = false;
    private $cacheDir;
    private $cacheFile;

    function __construct($user, $passwd) {
        if (!$user || !$passwd) {
            $this->invalid = true;
            $this->logStr .= "用户名或密码填写有误!\n";
            return;
        }
        $this->user = $user;
        $this->password = $passwd;

        $this->cacheDir = rtrim(cacheBaseDir(), '/') . '/';
        if (!is_dir($this->cacheDir)) @mkdir($this->cacheDir, 0755, true);
        $this->cacheFile = $this->cacheDir . getSafeFilename($user) . '.txt';
    }

    private function readCache() {
        if (!file_exists($this->cacheFile)) return null;
        $fp = @fopen($this->cacheFile, 'r');
        if (!$fp) return null;
        if (flock($fp, LOCK_SH)) {
            $data = stream_get_contents($fp);
            flock($fp, LOCK_UN);
            fclose($fp);
            $cache = json_decode((string)$data, true);
            if (!$cache || !isset($cache['expire_time']) || $cache['expire_time'] < time()) return null;
            return $cache;
        }
        fclose($fp);
        return null;
    }

    private function getCachedAccess($password) {
        $cache = $this->readCache();
        if ($cache && isset($cache['access']) && isset($cache['third_name'])
            && isset($cache['pwd_hash']) && password_verify($password, $cache['pwd_hash'])) {
            return [$cache['access'], $cache['third_name']];
        }
        return null;
    }

    private function writeCache($access, $third_name, $password) {
        $cacheData = [
            'access' => $access,
            'third_name' => $third_name,
            'user' => $this->user,
            'pwd_hash' => password_hash($password, PASSWORD_DEFAULT),
            'create_time' => time(),
            'expire_time' => time() + 604800
        ];
        $jsonData = json_encode($cacheData);
        if ($jsonData === false) return false;
        $tempFile = $this->cacheFile . '.tmp.' . uniqid('', true);
        $fp = @fopen($tempFile, 'w');
        if (!$fp) return false;
        if (fwrite($fp, $jsonData) !== strlen($jsonData)) {
            fclose($fp); @unlink($tempFile); return false;
        }
        fflush($fp); fclose($fp);
        @chmod($tempFile, 0600);
        if (@rename($tempFile, $this->cacheFile)) return true;
        @unlink($tempFile);
        return false;
    }

    private function clearCache() {
        if (file_exists($this->cacheFile)) @unlink($this->cacheFile);
    }

    private function encryptData($plain) {
        $key = 'xeNtBVqzDc6tuNTh';
        $iv = 'MAAAYAAAAAAAAABg';
        return openssl_encrypt($plain, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }

    private function curl($url, $data = null, $app_token = null, $ekv = false) {
        $lastError = '';
        for ($i = 0; $i < 2; $i++) {
            $ch = curl_init();
            $httpheader = [];
            $httpheader[] = "Accept: application/json";
            $httpheader[] = "Accept-Language: zh-CN,zh;q=0.8";
            $httpheader[] = "Connection: keep-alive";
            if ($ekv) $httpheader[] = "x-hm-ekv: 1";
            $httpheader[] = "app_name: com.xiaomi.hm.health";
            $httpheader[] = "appname: com.xiaomi.hm.health";
            $httpheader[] = "appplatform: android_phone";
            if ($app_token) $httpheader[] = "apptoken: " . $app_token;
            curl_setopt($ch, CURLOPT_HTTPHEADER, $httpheader);
            curl_setopt($ch, CURLOPT_URL, $url);
            if ($data) {
                if (is_array($data)) $data = http_build_query($data);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
                curl_setopt($ch, CURLOPT_POST, 1);
            }
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
            curl_setopt($ch, CURLOPT_TIMEOUT, 25);
            curl_setopt($ch, CURLOPT_USERAGENT, 'MiFit6.14.0 (OPD2413; Android 15; Density/2.625)');
            curl_setopt($ch, CURLOPT_HEADER, 1);
            $ret = curl_exec($ch);
            $lastError = curl_error($ch);
            $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            curl_close($ch);
            if ($ret !== false && is_int($headerSize) && $headerSize >= 0) {
                return ['header' => substr($ret, 0, $headerSize), 'body' => substr($ret, $headerSize)];
            }
        }
        throw new Exception('网络请求失败: ' . ($lastError ?: '未知错误'));
    }

    private function getAccess($username, $password) {
        $cached = $this->getCachedAccess($password);
        if ($cached) return $cached;

        $lockFile = $this->cacheDir . '.lock.' . md5($this->user);
        $lockFp = @fopen($lockFile, 'c');
        $gotLock = false;
        if ($lockFp) {
            for ($i = 0; $i < 75; $i++) {
                if (flock($lockFp, LOCK_EX | LOCK_NB)) { $gotLock = true; break; }
                usleep(200000);
            }
        } else {
            $gotLock = true;
        }
        try {
            if ($gotLock) {
                $cached = $this->getCachedAccess($password);
                if ($cached) return $cached;

                $third_name = strpos($username, '@') === false ? 'huami_phone' : 'email';
                if (strpos($username, '@') === false && preg_match('/^1[3-9]\d{9}$/', $username)) {
                    $username = '+86' . $username;
                }
                $url = 'https://api-user.zepp.com/v2/registrations/tokens';
                $data = [
                    'emailOrPhone' => $username,
                    'password' => $password,
                    'state' => 'REDIRECTION',
                    'client_id' => 'HuaMi',
                    'country_code' => 'CN',
                    'token' => 'access',
                    'redirect_uri' => 'https://s3-us-west-2.amazonaws.com/hm-registration/successsignin.html',
                ];
                $body = $this->encryptData(http_build_query($data));
                if ($body === false) throw new Exception('数据加密失败');
                $response = $this->curl($url, $body, null, true);
                if (preg_match("/access=(.*?)&/", $response['header'], $access)) {
                    $this->writeCache($access[1], $third_name, $password);
                    return [$access[1], $third_name];
                } elseif (preg_match("/refresh=(.*?)&/", $response['header'], $refresh)) {
                    $this->writeCache($refresh[1], $third_name, $password);
                    return [$refresh[1], $third_name];
                } elseif (strpos($response['header'], 'error=') !== false) {
                    $this->clearCache();
                    throw new Exception('账号或密码错误!');
                } else {
                    throw new Exception('登录token接口请求失败');
                }
            }
            $cached = $this->getCachedAccess($password);
            if ($cached) return $cached;
            throw new Exception('登录繁忙, 请稍后重试');
        } finally {
            if ($lockFp) {
                if ($gotLock) flock($lockFp, LOCK_UN);
                fclose($lockFp);
            }
        }
    }

    public function login() {
        try {
            list($access, $third_name) = $this->getAccess($this->user, $this->password);
            $this->logStr .= "获取access token成功\n";
            $url = 'https://account.zepp.com/v2/client/login';
            $data = [
                'app_name' => 'com.xiaomi.hm.health',
                'country_code' => 'CN',
                'code' => $access,
                'device_id' => 'efd38eeb-160d-44e4-9317-6df2145bcb0a',
                'device_model' => 'android_phone',
                'app_version' => '6.14.0',
                'grant_type' => 'access_token',
                'allow_registration' => 'false',
                'dn' => 'account.zepp.com,api-user.zepp.com,api-mifit.zepp.com,api-watch.zepp.com,app-analytics.zepp.com,api-analytics.huami.com,auth.zepp.com',
                'third_name' => $third_name,
                'source' => 'com.xiaomi.hm.health:6.14.0:50818',
                'lang' => 'zh',
            ];
            $response = $this->curl($url, $data);
            $arr = json_decode($response['body'], true);
            if (!$arr || !is_array($arr)) throw new Exception('登录接口请求失败');
            if (isset($arr['result']) && $arr['result'] == 'ok') {
                $token = $arr['token_info']['app_token'] ?? 0;
                $userid = $arr['token_info']['user_id'] ?? 0;
                if (!$token || !$userid) throw new Exception('登录接口返回数据不完整');
                return ['token' => $token, 'userid' => $userid, 'error' => ''];
            } else {
                $this->clearCache();
                $msg = is_string($arr['message'] ?? null) ? $arr['message'] : '登录失败';
                throw new Exception('登录失败: ' . $msg);
            }
        } catch (Exception $e) {
            $this->logStr .= "登录异常: " . $e->getMessage() . "\n";
            return ['token' => 0, 'userid' => 0, 'error' => $e->getMessage()];
        }
    }

    public function loginAndPostStep($step) {
        if ($this->invalid) return ["账号或密码配置有误", false];

        $loginResult = $this->login();
        $token = $loginResult['token'] ?? 0;
        $userid = $loginResult['userid'] ?? 0;
        $loginError = $loginResult['error'] ?? '';

        if (!$token) {
            $errorMsg = $loginError ? "登录失败: {$loginError}" : "登录失败!";
            return [$errorMsg, false];
        }

        try {
            $url = "https://api-mifit-cn.zepp.com/v1/data/band_data.json?t=" . time();

            // ===== 下面这行请替换成你原文件里 $json = '...' 那一整段（原样复制）=====
            $json = '[{"data_hr":"\/\/\/\/\/\/9L\/\/\/\/\/\/\/\/\/\/\/\/Vv\/\/\/\/\/\/\/\/\/\/\/0v\/\/\/\/\/\/\/\/\/\/\/9e\/\/\/\/\/0n\/a\/\/\/S\/\/\/\/\/\/\/\/\/\/\/\/0b\/\/\/\/\/\/\/\/\/\/1FK\/\/\/\/\/\/\/\/\/\/\/\/R\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/9PTFFpaf9L\/\/\/\/\/\/\/\/\/\/\/\/R\/\/\/\/\/\/\/\/\/\/\/\/0j\/\/\/\/\/\/\/\/\/\/\/9K\/\/\/\/\/\/\/\/\/\/\/\/Ov\/\/\/\/\/\/\/\/\/\/\/zf\/\/\/86\/zr\/Ov88\/zf\/Pf\/\/\/0v\/S\/8\/\/\/\/\/\/\/\/\/\/\/\/\/Sf\/\/\/\/\/\/\/\/\/\/\/z3\/\/\/\/\/\/0r\/Ov\/\/\/\/\/\/S\/9L\/zb\/Sf9K\/0v\/Rf9H\/zj\/Sf9K\/0\/\/N\/\/\/\/0D\/Sf83\/zr\/Pf9M\/0v\/Ov9e\/\/\/\/\/\/\/\/\/\/\/\/S\/\/\/\/\/\/\/\/\/\/\/\/zv\/\/z7\/O\/83\/zv\/N\/83\/zr\/N\/86\/z\/\/Nv83\/zn\/Xv84\/zr\/PP84\/zj\/N\/9e\/zr\/N\/89\/03\/P\/89\/z3\/Q\/9N\/0v\/Tv9C\/0H\/Of9D\/zz\/Of88\/z\/\/PP9A\/zr\/N\/86\/zz\/Nv87\/0D\/Ov84\/0v\/O\/84\/zf\/MP83\/zH\/Nv83\/zf\/N\/84\/zf\/Of82\/zf\/OP83\/zb\/Mv81\/zX\/R\/9L\/0v\/O\/9I\/0T\/S\/9A\/zn\/Pf89\/zn\/Nf9K\/07\/N\/83\/zn\/Nv83\/zv\/O\/9A\/0H\/Of8\/\/zj\/PP83\/zj\/S\/87\/zj\/Nv84\/zf\/Of83\/zf\/Of83\/zb\/Nv9L\/zj\/Nv82\/zb\/N\/85\/zf\/N\/9J\/zf\/Nv83\/zj\/Nv84\/0r\/Sv83\/zf\/MP\/\/\/zb\/Mv82\/zb\/Of85\/z7\/Nv8\/\/0r\/S\/85\/0H\/QP9B\/0D\/Nf89\/zj\/Ov83\/zv\/Nv8\/\/0f\/Sv9O\/0ZeXv\/\/\/\/\/\/\/\/\/\/\/1X\/\/\/\/\/\/\/\/\/\/\/9B\/\/\/\/\/\/\/\/\/\/\/\/TP\/\/\/1b\/\/\/\/\/\/0\/\/\/\/\/\/\/\/\/\/\/\/9N\/\/\/\/\/\/\/\/\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+","date":"' . date('Y-m-d') . '","data":[{"start":0,"stop":1439,"value":"UA8AUBQAUAwAUBoAUAEAYCcAUBkAUB4AUBgAUCAAUAEAUBkAUAwAYAsAYB8AYB0AYBgAYCoAYBgAYB4AUCcAUBsAUB8AUBwAUBIAYBkAYB8AUBoAUBMAUCEAUCIAYBYAUBwAUCAAUBgAUCAAUBcAYBsAYCUAATIPYD0KECQAYDMAYB0AYAsAYCAAYDwAYCIAYB0AYBcAYCQAYB0AYBAAYCMAYAoAYCIAYCEAYCYAYBsAYBUAYAYAYCIAYCMAUB0AUCAAUBYAUCoAUBEAUC8AUB0AUBYAUDMAUDoAUBkAUC0AUBQAUBwAUA0AUBsAUAoAUCEAUBYAUAwAUB4AUAwAUCcAUCYAUCwKYDUAAUUlEC8IYEMAYEgAYDoAYBAAUAMAUBkAWgAAWgAAWgAAWgAAWgAAUAgAWgAAUBAAUAQAUA4AUA8AUAkAUAIAUAYAUAcAUAIAWgAAUAQAUAkAUAEAUBkAUCUAWgAAUAYAUBEAWgAAUBYAWgAAUAYAWgAAWgAAWgAAWgAAUBcAUAcAWgAAUBUAUAoAUAIAWgAAUAQAUAYAUCgAWgAAUAgAWgAAWgAAUAwAWwAAXCMAUBQAWwAAUAIAWgAAWgAAWgAAWgAAWgAAWgAAWgAAWgAAWREAWQIAUAMAWSEAUDoAUDIAUB8AUCEAUC4AXB4AUA4AWgAAUBIAUA8AUBAAUCUAUCIAUAMAUAEAUAsAUAMAUCwAUBYAWgAAWgAAWgAAWgAAWgAAWgAAUAYAWgAAWgAAWgAAUAYAWwAAWgAAUAYAXAQAUAMAUBsAUBcAUCAAWwAAWgAAWgAAWgAAWgAAUBgAUB4AWgAAUAcAUAwAWQIAWQkAUAEAUAIAWgAAUAoAWgAAUAYAUB0AWgAAWgAAUAkAWgAAWSwAUBIAWgAAUC4AWSYAWgAAUAYAUAoAUAkAUAIAUAcAWgAAUAEAUBEAUBgAUBcAWRYAUA0AWSgAUB4AUDQAUBoAXA4AUA8AUBwAUA8AUA4AUA4AWgAAUAIAUCMAWgAAUCwAUBgAUAYAUAAAUAAAUAAAUAAAUAAAUAAAUAAAUAAAUAAAWwAAUAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAeSEAeQ8AcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBcAcAAAcAAAcCYOcBUAUAAAUAAAUAAAUAAAUAUAUAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCgAeQAAcAAAcAAAcAAAcAAAcAAAcAYAcAAAcBgAeQAAcAAAcAAAegAAegAAcAAAcAcAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCkAeQAAcAcAcAAAcAAAcAwAcAAAcAAAcAIAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCIAeQAAcAAAcAAAcAAAcAAAcAAAeRwAeQAAWgAAUAAAUAAAUAAAUAAAUAAAcAAAcAAAcBoAeScAeQAAegAAcBkAeQAAUAAAUAAAUAAAUAAAUAAAUAAAcAAAcAAAcAAAcAAAcAAAcAAAegAAegAAcAAAcAAAcBgAeQAAcAAAcAAAcAAAcAAAcAAAcAkAegAAegAAcAcAcAAAcAcAcAAAcAAAcAAAcAAAcA8AeQAAcAAAcAAAeRQAcAwAUAAAUAAAUAAAUAAAUAAAUAAAcAAAcBEAcA0AcAAAWQsAUAAAUAAAUAAAUAAAUAAAcAAAcAoAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAYAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBYAegAAcAAAcAAAegAAcAcAcAAAcAAAcAAAcAAAcAAAeRkAegAAegAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAEAcAAAcAAAcAAAcAUAcAQAcAAAcBIAeQAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBsAcAAAcAAAcBcAeQAAUAAAUAAAUAAAUAAAUAAAUBQAcBYAUAAAUAAAUAoAWRYAWTQAWQAAUAAAUAAAUAAAcAAAcAAAcAAAcAAAcAAAcAMAcAAAcAQAcAAAcAAAcAAAcDMAeSIAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBQAeQwAcAAAcAAAcAAAcAMAcAAAeSoAcA8AcDMAcAYAeQoAcAwAcFQAcEMAeVIAaTYAbBcNYAsAYBIAYAIAYAIAYBUAYCwAYBMAYDYAYCkAYDcAUCoAUCcAUAUAUBAAWgAAYBoAYBcAYCgAUAMAUAYAUBYAUA4AUBgAUAgAUAgAUAsAUAsAUA4AUAMAUAYAUAQAUBIAASsSUDAAUDAAUBAAYAYAUBAAUAUAUCAAUBoAUCAAUBAAUAoAYAIAUAQAUAgAUCcAUAsAUCIAUCUAUAoAUA4AUB8AUBkAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAA","tz":32,"did":"DA932FFFFE8816E7","src":24}],"summary":"{\"v\":6,\"slp\":{\"st\":1628296479,\"ed\":1628296479,\"dp\":0,\"lt\":0,\"wk\":0,\"usrSt\":-1440,\"usrEd\":-1440,\"wc\":0,\"is\":0,\"lb\":0,\"to\":0,\"dt\":0,\"rhr\":0,\"ss\":0},\"stp\":{\"ttl\":' . $step . ',\"dis\":10627,\"cal\":510,\"wk\":41,\"rn\":50,\"runDist\":7654,\"runCal\":397,\"stage\":[{\"start\":327,\"stop\":341,\"mode\":1,\"dis\":481,\"cal\":13,\"step\":680},{\"start\":342,\"stop\":367,\"mode\":3,\"dis\":2295,\"cal\":95,\"step\":2874},{\"start\":368,\"stop\":377,\"mode\":4,\"dis\":1592,\"cal\":88,\"step\":1664},{\"start\":378,\"stop\":386,\"mode\":3,\"dis\":1072,\"cal\":51,\"step\":1245},{\"start\":387,\"stop\":393,\"mode\":4,\"dis\":1036,\"cal\":57,\"step\":1124},{\"start\":394,\"stop\":398,\"mode\":3,\"dis\":488,\"cal\":19,\"step\":607},{\"start\":399,\"stop\":414,\"mode\":4,\"dis\":2220,\"cal\":120,\"step\":2371},{\"start\":415,\"stop\":427,\"mode\":3,\"dis\":1268,\"cal\":59,\"step\":1489},{\"start\":428,\"stop\":433,\"mode\":1,\"dis\":152,\"cal\":4,\"step\":238},{\"start\":434,\"stop\":444,\"mode\":3,\"dis\":2295,\"cal\":95,\"step\":2874},{\"start\":445,\"stop\":455,\"mode\":4,\"dis\":1592,\"cal\":88,\"step\":1664},{\"start\":456,\"stop\":466,\"mode\":3,\"dis\":1072,\"cal\":51,\"step\":1245},{\"start\":467,\"stop\":477,\"mode\":4,\"dis\":1036,\"cal\":57,\"step\":1124},{\"start\":478,\"stop\":488,\"mode\":3,\"dis\":488,\"cal\":19,\"step\":607},{\"start\":489,\"stop\":499,\"mode\":4,\"dis\":2220,\"cal\":120,\"step\":2371},{\"start\":500,\"stop\":511,\"mode\":3,\"dis\":1268,\"cal\":59,\"step\":1489},{\"start\":512,\"stop\":522,\"mode\":1,\"dis\":152,\"cal\":4,\"step\":238}]},\"goal\":8000,\"tz\":\"28800\"}","source":24,"type":0}]';
            $data = [
                'data_json' => $json,
                'userid' => $userid,
                'device_type' => '0',
                'last_sync_data_time' => time() . '',
                'last_deviceid' => 'C4D2D4FFFE8C5068',
            ];

            $response = $this->curl($url, $data, $token);
            $arr = json_decode($response['body'], true);
            if (!$arr) throw new Exception('修改步数接口请求失败');
            if (isset($arr['code']) && $arr['code'] == 1) {
                return ["修改步数({$step})", true];
            } else {
                $message = isset($arr['message']) && is_string($arr['message']) ? $arr['message'] : '未知错误';
                throw new Exception('修改步数失败: ' . $message);
            }
        } catch (Exception $e) {
            return [$e->getMessage(), false];
        }
    }
}

// ==================== 主执行逻辑 ====================
if ($_SERVER['REQUEST_METHOD'] === 'POST' || isset($_GET['token']) || isset($_POST['token'])) {
    if (isset($_GET['m'])) {
        jsonResponse(["error" => "not found"], 404);
    }

    $isWebForm = $_SERVER['REQUEST_METHOD'] === 'POST' && isSameOrigin();
    $validToken = (isset($_GET['token']) || isset($_POST['token'])) && param('token') === $token;
    if (!$validToken && !$isWebForm) {
        jsonResponse(["error" => "Token 验证失败"], 401);
    }

    list($rateLimitOk, $rateLimitMsg) = checkRateLimit();
    if (!$rateLimitOk) {
        jsonResponse(["error" => $rateLimitMsg], 429);
    }

    $user = param('user');
    $pwd = param('pwd');
    $step = param('step');

    if (!$user || !$pwd || $step === '') {
        jsonResponse(["error" => "参数不完整, 必须提供 user, pwd, step"], 400);
    }

    list($stepValid, $stepResult) = resolveStep($step);
    if (!$stepValid) {
        jsonResponse(["error" => $stepResult], 400);
    }

    try {
        $runner = new MiMotionRunner($user, $pwd);
        list($msg, $success) = $runner->loginAndPostStep($stepResult);
    } catch (\Throwable $e) {
        jsonResponse(["error" => "服务器内部错误: " . $e->getMessage()], 500);
    }

    $output = [
        "time" => date("Y-m-d H:i:s"),
        "user" => desensitizeUserName($user),
        "step" => $stepResult,
        "status" => $success ? "success" : "failed",
        "message" => $msg
    ];
    jsonResponse($output, 200);
}

jsonResponse(["error" => "请提供 user, pwd, step, token 参数"], 400);