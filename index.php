<?php
/**
 * xsukax GitHub CS App Manager
 * Secure Client-Side App Hosting Platform
 * @author xsukax
 */

session_start();

// Configuration
define('DATA_DIR', __DIR__ . '/apps_data');
define('APPS_DIR', DATA_DIR . '/apps');
define('META_FILE', DATA_DIR . '/apps.enc');
define('CAT_FILE', DATA_DIR . '/categories.enc');
define('SALT_FILE', DATA_DIR . '/salt.dat');
define('PASS_FILE', DATA_DIR . '/admin.pass');
define('COOKIE_NAME', 'xsukax_admin');
define('GENERAL_ID', 'general');

// Protected files that cannot be accessed
define('PROTECTED_FILES', [
    'apps.enc', 'categories.enc', 'salt.dat', 'admin.pass',
    '.enc', '.dat', '.pass', '.htaccess', '.git'
]);

// Initialize
if (!is_dir(DATA_DIR)) mkdir(DATA_DIR, 0755, true);
if (!is_dir(APPS_DIR)) mkdir(APPS_DIR, 0755, true);

// Security Class
class Security {
    public static function deriveKey($password, $salt) {
        return hash_pbkdf2('sha256', $password, $salt, 100000, 32, true);
    }
    
    public static function encrypt($data, $key) {
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt(json_encode($data), 'aes-256-cbc', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    public static function decrypt($data, $key) {
        $raw = base64_decode($data);
        $decrypted = openssl_decrypt(substr($raw, 16), 'aes-256-cbc', $key, 0, substr($raw, 0, 16));
        return json_decode($decrypted, true);
    }
    
    public static function getSalt() {
        if (!file_exists(SALT_FILE)) {
            file_put_contents(SALT_FILE, random_bytes(32));
        }
        return file_get_contents(SALT_FILE);
    }
}

// Data Manager
class DataManager {
    private $key;
    private $apps = [];
    private $categories = [];
    
    public function __construct($password) {
        $this->key = Security::deriveKey($password, Security::getSalt());
        $this->load();
    }
    
    private function load() {
        if (file_exists(META_FILE)) {
            try { $this->apps = Security::decrypt(file_get_contents(META_FILE), $this->key) ?: []; } catch (Exception $e) {}
        }
        if (file_exists(CAT_FILE)) {
            try { $this->categories = Security::decrypt(file_get_contents(CAT_FILE), $this->key) ?: []; } catch (Exception $e) {}
        }
        if (!isset($this->categories[GENERAL_ID])) {
            $this->categories[GENERAL_ID] = ['id' => GENERAL_ID, 'name' => 'General', 'protected' => true];
            $this->saveCategories();
        }
    }
    
    private function saveApps() {
        file_put_contents(META_FILE, Security::encrypt($this->apps, $this->key));
    }
    
    private function saveCategories() {
        file_put_contents(CAT_FILE, Security::encrypt($this->categories, $this->key));
    }
    
    public function getApps() { return array_values($this->apps); }
    public function getCategories() { return array_values($this->categories); }
    
    public function addCategory($name) {
        $id = bin2hex(random_bytes(8));
        $this->categories[$id] = ['id' => $id, 'name' => trim($name), 'protected' => false];
        $this->saveCategories();
        return $this->categories[$id];
    }
    
    public function renameCategory($id, $name) {
        if (!isset($this->categories[$id]) || $this->categories[$id]['protected']) {
            throw new Exception('Cannot modify this category');
        }
        $this->categories[$id]['name'] = trim($name);
        $this->saveCategories();
        return $this->categories[$id];
    }
    
    public function deleteCategory($id) {
        if (!isset($this->categories[$id]) || $this->categories[$id]['protected']) {
            throw new Exception('Cannot delete this category');
        }
        foreach ($this->apps as &$app) {
            if ($app['category_id'] === $id) $app['category_id'] = GENERAL_ID;
        }
        unset($this->categories[$id]);
        $this->saveCategories();
        $this->saveApps();
    }
    
    public function addApp($url, $categoryId, $token = '') {
        if (!preg_match('#github\.com/([^/]+)/([^/]+)#', $url, $m)) throw new Exception('Invalid GitHub URL');
        $owner = $m[1];
        $repo = rtrim($m[2], '.git');
        
        foreach ($this->apps as $app) {
            if ($app['repo'] === "$owner/$repo") throw new Exception('App already imported');
        }
        
        $data = $this->download($owner, $repo, $token);
        $id = bin2hex(random_bytes(16));
        
        $this->apps[$id] = [
            'id' => $id,
            'name' => str_replace(['-', '_'], ' ', $repo),
            'repo' => "$owner/$repo",
            'category_id' => $categoryId ?: GENERAL_ID,
            'added' => time(),
            'sha' => $data['sha'],
            'entry' => $data['entry']
        ];
        
        $this->saveApps();
        return $this->apps[$id];
    }
    
    private function download($owner, $repo, $token) {
        $headers = ['User-Agent: xsukax-CS-Manager'];
        if ($token) $headers[] = "Authorization: token $token";
        
        $contents = $this->apiCall("https://api.github.com/repos/$owner/$repo/contents", $headers);
        
        $hasHtml = false;
        $entry = 'index.html';
        foreach ($contents as $item) {
            $name = strtolower($item['name']);
            if (in_array($name, ['index.html', 'index.htm'])) {
                $hasHtml = true;
                $entry = $item['name'];
            }
            if (in_array($name, ['index.php', 'server.py', 'package.json', 'composer.json'])) {
                throw new Exception('Contains server-side code (not a CS app)');
            }
        }
        
        if (!$hasHtml) throw new Exception('No index.html found (not a CS app)');
        
        $commit = $this->apiCall("https://api.github.com/repos/$owner/$repo/commits/HEAD", $headers);
        
        $zipUrl = "https://github.com/$owner/$repo/archive/refs/heads/main.zip";
        if (!$this->downloadZip($zipUrl, $repo, $headers)) {
            $zipUrl = "https://github.com/$owner/$repo/archive/refs/heads/master.zip";
            if (!$this->downloadZip($zipUrl, $repo, $headers)) {
                throw new Exception('Download failed');
            }
        }
        
        return ['sha' => $commit['sha'], 'entry' => $entry];
    }
    
    private function apiCall($url, $headers) {
        $ctx = stream_context_create(['http' => ['header' => implode("\r\n", $headers)]]);
        $res = @file_get_contents($url, false, $ctx);
        if (!$res) throw new Exception('API request failed');
        return json_decode($res, true);
    }
    
    private function downloadZip($url, $repo, $headers) {
        $ctx = stream_context_create(['http' => ['header' => implode("\r\n", $headers), 'follow_location' => true]]);
        $data = @file_get_contents($url, false, $ctx);
        if (!$data) return false;
        
        $zip = new ZipArchive;
        $zipPath = APPS_DIR . "/$repo.zip";
        file_put_contents($zipPath, $data);
        
        if ($zip->open($zipPath) !== TRUE) return false;
        
        $temp = APPS_DIR . "/{$repo}_tmp";
        $final = APPS_DIR . "/$repo";
        
        $zip->extractTo($temp);
        $zip->close();
        unlink($zipPath);
        
        if (is_dir($final)) $this->rmdir($final);
        rename(glob($temp . '/*')[0], $final);
        $this->rmdir($temp);
        
        return true;
    }
    
    private function rmdir($dir) {
        if (!is_dir($dir)) return;
        foreach (array_diff(scandir($dir), ['.', '..']) as $f) {
            $path = "$dir/$f";
            is_dir($path) ? $this->rmdir($path) : unlink($path);
        }
        rmdir($dir);
    }
    
    public function moveApp($appId, $categoryId) {
        if (!isset($this->apps[$appId])) throw new Exception('App not found');
        $this->apps[$appId]['category_id'] = $categoryId;
        $this->saveApps();
    }
    
    public function deleteApp($id) {
        if (!isset($this->apps[$id])) throw new Exception('App not found');
        $repo = explode('/', $this->apps[$id]['repo'])[1];
        if (is_dir(APPS_DIR . "/$repo")) $this->rmdir(APPS_DIR . "/$repo");
        unset($this->apps[$id]);
        $this->saveApps();
    }
    
    public function checkUpdate($id, $token = '') {
        if (!isset($this->apps[$id])) throw new Exception('App not found');
        list($owner, $repo) = explode('/', $this->apps[$id]['repo']);
        $headers = ['User-Agent: xsukax-CS-Manager'];
        if ($token) $headers[] = "Authorization: token $token";
        $commit = $this->apiCall("https://api.github.com/repos/$owner/$repo/commits/HEAD", $headers);
        return [
            'current' => $this->apps[$id]['sha'],
            'latest' => $commit['sha'],
            'updated' => $this->apps[$id]['sha'] === $commit['sha']
        ];
    }
    
    public function export() {
        return [
            'version' => '1.0',
            'exported' => time(),
            'by' => 'xsukax GitHub CS App Manager',
            'categories' => $this->getCategories(),
            'apps' => $this->getApps()
        ];
    }
    
    public function import($data, $token = '') {
        if (!isset($data['categories']) || !isset($data['apps'])) throw new Exception('Invalid backup');
        
        $catMap = [GENERAL_ID => GENERAL_ID];
        foreach ($data['categories'] as $cat) {
            if ($cat['id'] === GENERAL_ID) continue;
            $newId = bin2hex(random_bytes(8));
            $catMap[$cat['id']] = $newId;
            $this->categories[$newId] = ['id' => $newId, 'name' => $cat['name'], 'protected' => false];
        }
        $this->saveCategories();
        
        $imported = 0;
        $downloaded = 0;
        $failed = [];
        
        foreach ($data['apps'] as $app) {
            // Check if app already exists
            $exists = false;
            foreach ($this->apps as $a) {
                if ($a['repo'] === $app['repo']) { $exists = true; break; }
            }
            if ($exists) continue;
            
            // Check if app files exist locally
            list($owner, $repo) = explode('/', $app['repo']);
            $appPath = APPS_DIR . "/$repo";
            
            // If app files don't exist, download them
            if (!is_dir($appPath)) {
                try {
                    $headers = ['User-Agent: xsukax-CS-Manager'];
                    if ($token) $headers[] = "Authorization: token $token";
                    
                    // Try to download from GitHub
                    $zipUrl = "https://github.com/{$app['repo']}/archive/refs/heads/main.zip";
                    if (!$this->downloadZip($zipUrl, $repo, $headers)) {
                        $zipUrl = "https://github.com/{$app['repo']}/archive/refs/heads/master.zip";
                        if (!$this->downloadZip($zipUrl, $repo, $headers)) {
                            $failed[] = $app['name'];
                            continue; // Skip this app if download fails
                        }
                    }
                    $downloaded++;
                } catch (Exception $e) {
                    $failed[] = $app['name'];
                    continue; // Skip this app if download fails
                }
            }
            
            $id = bin2hex(random_bytes(16));
            $this->apps[$id] = [
                'id' => $id,
                'name' => $app['name'],
                'repo' => $app['repo'],
                'category_id' => $catMap[$app['category_id']] ?? GENERAL_ID,
                'added' => time(),
                'sha' => $app['sha'],
                'entry' => $app['entry']
            ];
            $imported++;
        }
        $this->saveApps();
        
        return [
            'cats' => count($data['categories']) - 1, 
            'apps' => $imported, 
            'downloaded' => $downloaded,
            'skipped' => count($data['apps']) - $imported,
            'failed' => $failed
        ];
    }
    
    public function reEncrypt($newPassword) {
        $this->key = Security::deriveKey($newPassword, Security::getSalt());
        $this->saveApps();
        $this->saveCategories();
    }
}

// Auth Manager
class Auth {
    public static function init() {
        if (!file_exists(PASS_FILE)) {
            file_put_contents(PASS_FILE, password_hash('admin@123', PASSWORD_BCRYPT));
        }
    }
    
    public static function login($password) {
        self::init();
        if (password_verify($password, file_get_contents(PASS_FILE))) {
            $_SESSION['token'] = bin2hex(random_bytes(32));
            $_SESSION['pass'] = $password;
            setcookie(COOKIE_NAME, $_SESSION['token'], time() + 604800, '/', '', false, true);
            return true;
        }
        return false;
    }
    
    public static function check() {
        return isset($_SESSION['token']) && isset($_COOKIE[COOKIE_NAME]) && $_SESSION['token'] === $_COOKIE[COOKIE_NAME];
    }
    
    public static function logout() {
        unset($_SESSION['token'], $_SESSION['pass']);
        setcookie(COOKIE_NAME, '', time() - 3600, '/');
    }
    
    public static function changePassword($old, $new) {
        self::init();
        if (!password_verify($old, file_get_contents(PASS_FILE))) throw new Exception('Incorrect password');
        file_put_contents(PASS_FILE, password_hash($new, PASSWORD_BCRYPT));
        (new DataManager($old))->reEncrypt($new);
        $_SESSION['pass'] = $new;
    }
    
    public static function getPassword() {
        return $_SESSION['pass'] ?? null;
    }
}

// Security check for file access
function isProtectedFile($path) {
    foreach (PROTECTED_FILES as $pattern) {
        if (strpos($path, $pattern) !== false) return true;
    }
    return false;
}

// Router
$action = $_GET['action'] ?? 'home';
$appId = $_GET['app'] ?? null;

// Serve app to public
if ($appId && $action === 'view') {
    Auth::init();
    $password = Auth::getPassword() ?? 'admin@123';
    $dm = new DataManager($password);
    $apps = $dm->getApps();
    
    foreach ($apps as $app) {
        if ($app['id'] === $appId) {
            $repo = explode('/', $app['repo'])[1];
            $file = $_GET['file'] ?? $app['entry'];
            $file = str_replace(['../', '..\\'], '', $file);
            
            // Security: Block protected files
            if (isProtectedFile($file)) {
                http_response_code(403);
                die('403 Forbidden');
            }
            
            $path = APPS_DIR . "/$repo/$file";
            
            if (file_exists($path) && strpos(realpath($path), realpath(APPS_DIR . "/$repo")) === 0) {
                $ext = pathinfo($path, PATHINFO_EXTENSION);
                $types = [
                    'html' => 'text/html', 'css' => 'text/css', 'js' => 'application/javascript',
                    'json' => 'application/json', 'png' => 'image/png', 'jpg' => 'image/jpeg',
                    'jpeg' => 'image/jpeg', 'gif' => 'image/gif', 'svg' => 'image/svg+xml',
                    'woff' => 'font/woff', 'woff2' => 'font/woff2', 'ttf' => 'font/ttf'
                ];
                header('Content-Type: ' . ($types[$ext] ?? 'application/octet-stream'));
                readfile($path);
                exit;
            }
        }
    }
    http_response_code(404);
    die('404 Not Found');
}

// API
if ($action === 'api') {
    header('Content-Type: application/json');
    
    if (!Auth::check() && $_POST['ep'] !== 'login') {
        die(json_encode(['ok' => false, 'err' => 'Not authenticated']));
    }
    
    try {
        $ep = $_POST['ep'] ?? '';
        
        switch ($ep) {
            case 'login':
                echo json_encode(['ok' => Auth::login($_POST['pass'] ?? '')]);
                break;
                
            case 'logout':
                Auth::logout();
                echo json_encode(['ok' => true]);
                break;
                
            case 'change_pass':
                Auth::changePassword($_POST['old'] ?? '', $_POST['new'] ?? '');
                echo json_encode(['ok' => true]);
                break;
                
            case 'cats':
                $dm = new DataManager(Auth::getPassword());
                echo json_encode(['ok' => true, 'data' => $dm->getCategories()]);
                break;
                
            case 'add_cat':
                $dm = new DataManager(Auth::getPassword());
                echo json_encode(['ok' => true, 'data' => $dm->addCategory($_POST['name'] ?? '')]);
                break;
                
            case 'rename_cat':
                $dm = new DataManager(Auth::getPassword());
                echo json_encode(['ok' => true, 'data' => $dm->renameCategory($_POST['id'], $_POST['name'])]);
                break;
                
            case 'del_cat':
                $dm = new DataManager(Auth::getPassword());
                $dm->deleteCategory($_POST['id']);
                echo json_encode(['ok' => true]);
                break;
                
            case 'apps':
                $dm = new DataManager(Auth::getPassword());
                echo json_encode(['ok' => true, 'data' => $dm->getApps()]);
                break;
                
            case 'add_app':
                $dm = new DataManager(Auth::getPassword());
                echo json_encode(['ok' => true, 'data' => $dm->addApp($_POST['url'], $_POST['cat'], $_POST['token'] ?? '')]);
                break;
                
            case 'move_app':
                $dm = new DataManager(Auth::getPassword());
                $dm->moveApp($_POST['app'], $_POST['cat']);
                echo json_encode(['ok' => true]);
                break;
                
            case 'del_app':
                $dm = new DataManager(Auth::getPassword());
                $dm->deleteApp($_POST['id']);
                echo json_encode(['ok' => true]);
                break;
                
            case 'check':
                $dm = new DataManager(Auth::getPassword());
                echo json_encode(['ok' => true, 'data' => $dm->checkUpdate($_POST['id'], $_POST['token'] ?? '')]);
                break;
                
            case 'export':
                $dm = new DataManager(Auth::getPassword());
                echo json_encode(['ok' => true, 'data' => $dm->export()]);
                break;
                
            case 'import':
                $dm = new DataManager(Auth::getPassword());
                $data = json_decode($_POST['data'], true);
                $token = $_POST['token'] ?? '';
                echo json_encode(['ok' => true, 'data' => $dm->import($data, $token)]);
                break;
                
            default:
                echo json_encode(['ok' => false, 'err' => 'Unknown endpoint']);
        }
    } catch (Exception $e) {
        echo json_encode(['ok' => false, 'err' => $e->getMessage()]);
    }
    exit;
}

$logged = Auth::check();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>xsukax GitHub CS App Manager</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f6f8fa; }
.modal { display: none; position: fixed; inset: 0; background: rgba(27,31,35,0.5); z-index: 50; align-items: center; justify-content: center; }
.modal.show { display: flex; }
.toast { position: fixed; top: 20px; right: 20px; min-width: 300px; padding: 12px 16px; border-radius: 6px; box-shadow: 0 8px 24px rgba(0,0,0,0.12); z-index: 100; animation: slide 0.3s; }
.toast.success { background: #d1f4e0; border-left: 4px solid #28a745; color: #155724; }
.toast.error { background: #f8d7da; border-left: 4px solid #d73a49; color: #721c24; }
.toast.info { background: #d1ecf1; border-left: 4px solid #0366d6; color: #0c5460; }
@keyframes slide { from { transform: translateX(400px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
.card { background: white; border: 1px solid #d0d7de; border-radius: 6px; transition: all 0.2s; }
.card:hover { border-color: #0969da; box-shadow: 0 3px 12px rgba(0,0,0,0.1); }
.btn { padding: 6px 16px; border-radius: 6px; font-weight: 500; cursor: pointer; border: 1px solid transparent; transition: all 0.15s; font-size: 14px; }
.btn-primary { background: #2da44e; color: white; }
.btn-primary:hover { background: #2c974b; }
.btn-secondary { background: #f6f8fa; color: #24292f; border-color: rgba(27,31,35,0.15); }
.btn-secondary:hover { background: #f3f4f6; }
.btn-danger { background: #d1242f; color: white; }
.btn-danger:hover { background: #b52a34; }
input, select { border: 1px solid #d0d7de; border-radius: 6px; padding: 5px 12px; width: 100%; font-size: 14px; }
input:focus, select:focus { outline: none; border-color: #0969da; box-shadow: 0 0 0 3px rgba(9,105,218,0.12); }
.badge { display: inline-block; padding: 2px 7px; border-radius: 12px; font-size: 12px; font-weight: 500; background: #ddf4ff; color: #0969da; border: 1px solid #54aeff; }
.spinner { border: 2px solid #f3f3f3; border-top: 2px solid #0969da; border-radius: 50%; width: 20px; height: 20px; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.cat-item { padding: 10px 12px; border-radius: 6px; margin-bottom: 4px; cursor: pointer; transition: all 0.15s; display: flex; justify-content: space-between; align-items: center; }
.cat-item:hover { background: #f3f4f6; }
.cat-item.active { background: #ddf4ff; border-left: 3px solid #0969da; font-weight: 600; }
.cat-item.protected { background: #f6f8fa; }
.cat-item.protected.active { background: #ddf4ff; }
</style>
</head>
<body>
<div id="toasts"></div>

<?php if (!$logged): ?>
<div class="min-h-screen flex items-center justify-center p-4">
    <div class="card p-8 max-w-md w-full">
        <div class="text-center mb-6">
            <h1 class="text-2xl font-bold text-gray-900 mb-1">xsukax</h1>
            <h2 class="text-lg font-semibold text-gray-700 mb-1">GitHub CS App Manager</h2>
            <p class="text-sm text-gray-600">Client-Side Apps Platform</p>
        </div>
        <form id="loginForm" class="space-y-4">
            <div>
                <label class="block text-sm font-medium mb-1">Password</label>
                <input type="password" id="loginPass" required>
            </div>
            <button type="submit" class="btn btn-primary w-full">Sign In</button>
            <p class="text-xs text-gray-500 text-center">Default: admin@123</p>
        </form>
    </div>
</div>
<?php else: ?>
<header class="bg-white border-b border-gray-200 sticky top-0 z-40">
    <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
        <div>
            <h1 class="text-xl font-bold">xsukax GitHub CS App Manager</h1>
            <p class="text-xs text-gray-600">Github Client-Side Apps Platform</p>
        </div>
        <div class="flex gap-2">
            <button onclick="showBackup()" class="btn btn-secondary">Backup</button>
            <button onclick="showPass()" class="btn btn-secondary">Password</button>
            <button onclick="logout()" class="btn btn-secondary">Logout</button>
        </div>
    </div>
</header>

<main class="max-w-7xl mx-auto px-4 py-6">
    <!-- Add App -->
    <section class="card p-6 mb-6">
        <h2 class="text-lg font-bold mb-4">Import CS App</h2>
        <form id="addForm" class="space-y-4">
            <div class="grid md:grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm font-medium mb-1">GitHub URL</label>
                    <input type="url" id="url" placeholder="https://github.com/user/repo" required>
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1">Category</label>
                    <select id="cat"></select>
                </div>
            </div>
            <div>
                <label class="block text-sm font-medium mb-1">Token (optional)</label>
                <input type="text" id="token" placeholder="ghp_...">
            </div>
            <button type="submit" class="btn btn-primary">
                <span id="addText">Import App</span>
                <span id="addSpinner" class="spinner" style="display:none;"></span>
            </button>
        </form>
    </section>

    <!-- Categories & Apps -->
    <div class="grid lg:grid-cols-4 gap-6">
        <!-- Sidebar -->
        <aside>
            <div class="card p-4">
                <div class="flex justify-between items-center mb-3">
                    <h3 class="font-bold">Categories</h3>
                    <button onclick="showAddCat()" class="text-xl text-green-600">+</button>
                </div>
                <div class="cat-item active" onclick="filterCat('all')">
                    <div>
                        <div class="text-sm">All Apps</div>
                        <div class="text-xs text-gray-500" id="allCount">0</div>
                    </div>
                </div>
                <div id="catList"></div>
            </div>
        </aside>

        <!-- Apps -->
        <div class="lg:col-span-3">
            <div class="mb-4">
                <h2 class="text-lg font-bold" id="filterTitle">All Apps</h2>
            </div>
            <div id="apps" class="grid md:grid-cols-2 gap-4"></div>
        </div>
    </div>
</main>

<!-- Modals -->
<div id="passModal" class="modal">
    <div class="card p-6 max-w-md w-full">
        <h3 class="font-bold mb-4">Change Password</h3>
        <form id="passForm" class="space-y-4">
            <div>
                <label class="block text-sm mb-1">Current</label>
                <input type="password" id="oldPass" required>
            </div>
            <div>
                <label class="block text-sm mb-1">New</label>
                <input type="password" id="newPass" required>
            </div>
            <div class="flex gap-2">
                <button type="button" onclick="hide('passModal')" class="btn btn-secondary flex-1">Cancel</button>
                <button type="submit" class="btn btn-primary flex-1">Update</button>
            </div>
        </form>
    </div>
</div>

<div id="catModal" class="modal">
    <div class="card p-6 max-w-md w-full">
        <h3 class="font-bold mb-4" id="catTitle">Add Category</h3>
        <form id="catForm" class="space-y-4">
            <input type="hidden" id="catId">
            <div>
                <label class="block text-sm mb-1">Name</label>
                <input type="text" id="catName" required>
            </div>
            <div class="flex gap-2">
                <button type="button" onclick="hide('catModal')" class="btn btn-secondary flex-1">Cancel</button>
                <button type="submit" class="btn btn-primary flex-1">Save</button>
            </div>
        </form>
    </div>
</div>

<div id="backupModal" class="modal">
    <div class="card p-6 max-w-xl w-full">
        <h3 class="font-bold mb-4">Backup & Restore</h3>
        <div class="space-y-4">
            <div class="border rounded p-4">
                <h4 class="font-semibold mb-2">Export</h4>
                <p class="text-sm text-gray-600 mb-3">Download all data as JSON</p>
                <button onclick="exportData()" class="btn btn-primary">Export</button>
            </div>
            <div class="border rounded p-4">
                <h4 class="font-semibold mb-2">Import</h4>
                <p class="text-sm text-gray-600 mb-3">Restore from backup (will download missing apps)</p>
                <input type="file" id="importFile" accept=".json" class="mb-2">
                <input type="text" id="importToken" placeholder="GitHub Token (optional)" class="mb-2">
                <button onclick="importData()" class="btn btn-primary">Import & Download</button>
            </div>
        </div>
        <button onclick="hide('backupModal')" class="btn btn-secondary w-full mt-4">Close</button>
    </div>
</div>
<?php endif; ?>

<script>
const api = async (ep, data = {}) => {
    const fd = new FormData();
    fd.append('ep', ep);
    Object.keys(data).forEach(k => fd.append(k, data[k]));
    const res = await fetch('?action=api', { method: 'POST', body: fd });
    return res.json();
};

const toast = (msg, type = 'info') => {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    document.getElementById('toasts').appendChild(el);
    setTimeout(() => el.remove(), 4000);
};

const show = id => document.getElementById(id).classList.add('show');
const hide = id => document.getElementById(id).classList.remove('show');

<?php if (!$logged): ?>
document.getElementById('loginForm').onsubmit = async (e) => {
    e.preventDefault();
    const r = await api('login', { pass: document.getElementById('loginPass').value });
    r.ok ? location.reload() : toast('Invalid password', 'error');
};
<?php else: ?>
let cats = [], apps = [], filter = 'all';

const logout = async () => { await api('logout'); location.reload(); };
const showPass = () => show('passModal');
const showBackup = () => show('backupModal');

document.getElementById('passForm').onsubmit = async (e) => {
    e.preventDefault();
    const r = await api('change_pass', { 
        old: document.getElementById('oldPass').value,
        new: document.getElementById('newPass').value
    });
    if (r.ok) {
        toast('Password updated!', 'success');
        hide('passModal');
        e.target.reset();
    } else {
        toast(r.err, 'error');
    }
};

const loadCats = async () => {
    const r = await api('cats');
    if (r.ok) {
        cats = r.data;
        renderCats();
        updateSelects();
    }
};

const renderCats = () => {
    document.getElementById('allCount').textContent = `${apps.length} apps`;
    
    document.getElementById('catList').innerHTML = cats.map(c => {
        const count = apps.filter(a => a.category_id === c.id).length;
        const isActive = filter === c.id;
        
        return `
            <div class="cat-item ${isActive ? 'active' : ''} ${c.protected ? 'protected' : ''}" onclick="filterCat('${c.id}')">
                <div>
                    <div class="text-sm">${c.name}</div>
                    <div class="text-xs text-gray-500">${count} apps</div>
                </div>
                ${!c.protected ? `
                    <div class="flex gap-1" onclick="event.stopPropagation()">
                        <button onclick="editCat('${c.id}', '${c.name}')" class="text-sm">✏️</button>
                        <button onclick="delCat('${c.id}')" class="text-sm">🗑️</button>
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');
};

const filterCat = (catId) => {
    filter = catId;
    
    // Update active state
    document.querySelectorAll('.cat-item').forEach(el => el.classList.remove('active'));
    event.currentTarget.classList.add('active');
    
    // Update title
    if (catId === 'all') {
        document.getElementById('filterTitle').textContent = 'All Apps';
    } else {
        const cat = cats.find(c => c.id === catId);
        document.getElementById('filterTitle').textContent = cat ? cat.name : 'Apps';
    }
    
    renderApps();
};

const updateSelects = () => {
    document.getElementById('cat').innerHTML = cats.map(c => 
        `<option value="${c.id}">${c.name}</option>`
    ).join('');
};

const showAddCat = () => {
    document.getElementById('catTitle').textContent = 'Add Category';
    document.getElementById('catId').value = '';
    document.getElementById('catName').value = '';
    show('catModal');
};

const editCat = (id, name) => {
    document.getElementById('catTitle').textContent = 'Rename Category';
    document.getElementById('catId').value = id;
    document.getElementById('catName').value = name;
    show('catModal');
};

document.getElementById('catForm').onsubmit = async (e) => {
    e.preventDefault();
    const id = document.getElementById('catId').value;
    const name = document.getElementById('catName').value;
    
    const r = id 
        ? await api('rename_cat', { id, name })
        : await api('add_cat', { name });
    
    if (r.ok) {
        toast(id ? 'Category renamed!' : 'Category added!', 'success');
        hide('catModal');
        loadCats();
        loadApps();
    } else {
        toast(r.err, 'error');
    }
};

const delCat = async (id) => {
    const c = cats.find(x => x.id === id);
    const count = apps.filter(a => a.category_id === id).length;
    if (!confirm(`Delete ${c.name}?${count > 0 ? ` ${count} apps will move to General.` : ''}`)) return;
    
    const r = await api('del_cat', { id });
    if (r.ok) {
        toast('Category deleted', 'success');
        if (filter === id) filter = 'all';
        loadCats();
        loadApps();
    } else {
        toast(r.err, 'error');
    }
};

const loadApps = async () => {
    const r = await api('apps');
    if (r.ok) {
        apps = r.data;
        renderApps();
        renderCats();
    }
};

const renderApps = () => {
    const filtered = filter === 'all' ? apps : apps.filter(a => a.category_id === filter);
    
    if (filtered.length === 0) {
        document.getElementById('apps').innerHTML = '<div class="col-span-full text-center py-12 text-gray-500">No apps in this category</div>';
        return;
    }
    
    document.getElementById('apps').innerHTML = filtered.map(a => {
        const cat = cats.find(c => c.id === a.category_id);
        const url = `?action=view&app=${a.id}`;
        
        return `
            <div class="card p-4">
                <div class="flex justify-between items-start mb-2">
                    <h3 class="font-bold">${a.name}</h3>
                    <span class="badge">${cat?.name || 'General'}</span>
                </div>
                <p class="text-xs text-gray-600 mb-3 font-mono">${a.repo}</p>
                <div class="text-xs text-gray-500 mb-3">
                    ${new Date(a.added * 1000).toLocaleDateString()}
                </div>
                <div class="flex gap-2 mb-3">
                    <a href="${url}" target="_blank" class="btn btn-primary flex-1 text-center text-xs">Open</a>
                    <button onclick="check('${a.id}')" class="btn btn-secondary text-xs">🔄</button>
                    <button onclick="delApp('${a.id}')" class="btn btn-danger text-xs">🗑️</button>
                </div>
                <select onchange="move('${a.id}', this.value)" class="text-xs">
                    ${cats.map(c => 
                        `<option value="${c.id}" ${c.id === a.category_id ? 'selected' : ''}>${c.name}</option>`
                    ).join('')}
                </select>
            </div>
        `;
    }).join('');
};

document.getElementById('addForm').onsubmit = async (e) => {
    e.preventDefault();
    
    const text = document.getElementById('addText');
    const spinner = document.getElementById('addSpinner');
    const btn = e.target.querySelector('button');
    
    btn.disabled = true;
    text.style.display = 'none';
    spinner.style.display = 'inline-block';
    
    const r = await api('add_app', {
        url: document.getElementById('url').value,
        cat: document.getElementById('cat').value,
        token: document.getElementById('token').value
    });
    
    btn.disabled = false;
    text.style.display = 'inline';
    spinner.style.display = 'none';
    
    if (r.ok) {
        toast(`App "${r.data.name}" imported!`, 'success');
        e.target.reset();
        loadApps();
    } else {
        toast(r.err, 'error');
    }
};

const move = async (app, cat) => {
    const r = await api('move_app', { app, cat });
    if (r.ok) {
        toast('App moved!', 'success');
        loadApps();
    }
};

const check = async (id) => {
    toast('Checking...', 'info');
    const r = await api('check', { id });
    if (r.ok) {
        toast(r.data.updated ? 'Up to date!' : `Update available: ${r.data.current.substr(0,7)} → ${r.data.latest.substr(0,7)}`, r.data.updated ? 'success' : 'info');
    }
};

const delApp = async (id) => {
    if (!confirm('Delete this app?')) return;
    const r = await api('del_app', { id });
    if (r.ok) {
        toast('App deleted', 'success');
        loadApps();
    }
};

const exportData = async () => {
    const r = await api('export');
    if (r.ok) {
        const blob = new Blob([JSON.stringify(r.data, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `xsukax-backup-${Date.now()}.json`;
        a.click();
        toast('Exported!', 'success');
    }
};

const importData = async () => {
    const file = document.getElementById('importFile').files[0];
    if (!file) return toast('Select a file', 'error');
    
    const token = document.getElementById('importToken').value;
    
    const reader = new FileReader();
    reader.onload = async (e) => {
        toast('Importing and downloading apps...', 'info');
        const r = await api('import', { data: e.target.result, token });
        if (r.ok) {
            const { cats, apps, downloaded, skipped, failed } = r.data;
            let msg = `Imported: ${cats} categories, ${apps} apps`;
            if (downloaded > 0) msg += `, ${downloaded} downloaded`;
            if (skipped > 0) msg += ` (${skipped} skipped)`;
            if (failed && failed.length > 0) msg += `\nFailed: ${failed.join(', ')}`;
            toast(msg, failed && failed.length > 0 ? 'info' : 'success');
            document.getElementById('importFile').value = '';
            document.getElementById('importToken').value = '';
            loadCats();
            loadApps();
        } else {
            toast(r.err, 'error');
        }
    };
    reader.readAsText(file);
};

loadCats();
loadApps();
<?php endif; ?>
</script>
</body>
</html>