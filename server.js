const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const https = require('https');

// --- MOVE THIS BLOCK UP HERE ---
function auth(requiredRole) {
  return (req, res, next) => {
    let token = req.headers['authorization']?.split(' ')[1];
    // Try cookie if not in header
    if (!token && req.headers.cookie) {
      const m = req.headers.cookie.match(/(?:^|;\s*)token=([^;]+)/);
      if (m && m[1]) token = decodeURIComponent(m[1]);
    }
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = payload;
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      next();
    } catch {
      res.status(401).json({ error: 'Invalid token' });
    }
  };
}
// --- END MOVE ---

// Helper: Load settings (with defaults)
function loadSettings() {
  let defaults = {
    allowRegister: true,
    allowLogin: true,
    allowUpload: true,
    uploadLimit: 150,
    port: 3000,
    ftpPort: 2121,
    ownerUsername: 'owner',
    ownerPassword: 'ownerpassword',
    storageDir: 'storage',
    jwtSecret: 'supersecretkey',
    maxUsers: 100,
    defaultUserRole: 'user',
    sessionTimeoutMinutes: 60,
    logLevel: 'info',
    enableFileVersioning: false,
    maxFileVersions: 5,
    maintenanceMode: false,
    welcomeMessage: 'Welcome to FTP Web Client!',
    adminContact: '',
    passwordMinLength: 6,
    passwordRequireNumbers: true,
    passwordRequireUppercase: false,
    passwordRequireSpecial: false
  };
  const SETTINGS_FILE = path.join(__dirname, 'settings.json');
  if (!fs.existsSync(SETTINGS_FILE)) return defaults;
  let fileSettings = JSON.parse(fs.readFileSync(SETTINGS_FILE));
  return { ...defaults, ...fileSettings };
}
function saveSettings(settings) {
  const SETTINGS_FILE = path.join(__dirname, 'settings.json');
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
}

// Load settings once at startup and whenever needed
let settings = loadSettings();

const USERS_FILE = path.join(__dirname, 'users.json');
const STORAGE_DIR = path.join(__dirname, settings.storageDir || 'storage');
const JWT_SECRET = settings.jwtSecret || 'supersecretkey';
const OWNER_USERNAME = settings.ownerUsername || 'owner';
const OWNER_PASSWORD = settings.ownerPassword || 'ownerpassword';

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '2048mb' }));
app.use(express.static('frontend')); // Serve frontend

// Helper: Load users
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return {};
  return JSON.parse(fs.readFileSync(USERS_FILE));
}
// Helper: Save users
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Helper: Get users for admin (hide plain passwords, only show hash and limit)
function getUsersForAdmin() {
  const users = loadUsers();
  return Object.entries(users).map(([username, data]) => ({
    username,
    passwordHash: data.password, // bcrypt hash
    disabled: data.enabled === false,
    role: data.role,
    limitGB: data.limitGB !== undefined ? data.limitGB : (data.role === 'owner' ? null : 5)
  }));
}

// Owner: Verify owner status
app.post('/api/admin/verify-owner', auth('owner'), (req, res) => {
  res.json({ isOwner: true });
});

// Owner: List users (show only hash, not plain password)
app.get('/api/admin/users', auth('owner'), (req, res) => {
  res.json(getUsersForAdmin());
});

// Owner: Change user password (update both hash and plain for demo)
app.post('/api/admin/user-password', auth('owner'), (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  const users = loadUsers();
  if (!users[username]) return res.status(404).json({ error: 'User not found' });
  users[username].password = bcrypt.hashSync(password, 10);
  users[username].plain = password;
  saveUsers(users);
  res.json({ success: true });
});

// Owner: Enable/disable user
app.post('/api/admin/user-disable', auth('owner'), (req, res) => {
  const { username, disable } = req.body;
  if (username === 'owner') return res.status(400).json({ error: 'Cannot disable owner' });
  const users = loadUsers();
  if (!users[username]) return res.status(404).json({ error: 'User not found' });
  users[username].enabled = !disable ? true : false;
  saveUsers(users);
  res.json({ success: true });
});

// Owner: Delete user
app.post('/api/admin/user-delete', auth('owner'), (req, res) => {
  const { username } = req.body;
  if (!username || username === 'owner') return res.status(400).json({ error: 'Invalid user' });
  const users = loadUsers();
  if (!users[username]) return res.status(404).json({ error: 'User not found' });
  delete users[username];
  saveUsers(users);
  // Optionally, delete user's storage directory
  const userDir = path.join(STORAGE_DIR, username);
  if (fs.existsSync(userDir)) {
    fs.rmSync(userDir, { recursive: true, force: true });
  }
  res.json({ success: true });
});

// Owner: Get global settings (live reload)
app.get('/api/admin/settings', auth('owner'), (req, res) => {
  try {
    res.json(loadSettings());
  } catch (e) {
    res.status(500).json({ error: 'Failed to load settings', details: e.message });
  }
});

// Owner: Set global settings (live update)
app.post('/api/admin/settings', auth('owner'), (req, res) => {
  // Only allow changing known settings
  const allowed = ['allowRegister','allowLogin','allowUpload','uploadLimit'];
  let settings = loadSettings();
  if (req.body.key && allowed.includes(req.body.key)) {
    // For uploadLimit, parse and store as string with units if user entered a string
    if (req.body.key === 'uploadLimit') {
      let v = req.body.value;
      if (typeof v === 'number') v = v + 'MB';
      else if (typeof v === 'string') v = v.trim();
      settings[req.body.key] = v;
    } else {
      settings[req.body.key] = !!req.body.value;
    }
    saveSettings(settings);
    return res.json({ success: true });
  }
  // If full settings object is sent (legacy), just save
  if (typeof req.body === 'object' && !req.body.key) {
    saveSettings(req.body);
    return res.json({ success: true });
  }
  res.status(400).json({ error: 'Invalid request' });
});

// Register (store both plain and hash for demo, NOT for production, and set default limitGB)
app.post('/api/register', (req, res) => {
  const settings = loadSettings();
  if (settings.allowRegister === false) return res.status(403).json({ error: 'Registration disabled' });
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  // Only allow lowercase letters and numbers for usernames
  if (!/^[a-z0-9]+$/.test(username)) {
    return res.status(400).json({ error: 'Username must be lowercase letters and numbers only (no spaces, capitals, or special characters).' });
  }
  const users = loadUsers();
  if (users[username]) return res.status(400).json({ error: 'User exists' });
  const hash = bcrypt.hashSync(password, 10);
  // Use settings.defaultUserRole and settings.maxUsers
  if (Object.keys(users).length >= (settings.maxUsers || 100)) {
    return res.status(400).json({ error: 'User limit reached' });
  }
  users[username] = { password: hash, plain: password, role: settings.defaultUserRole || 'user', enabled: true, limitGB: 5 };
  saveUsers(users);
  const userDir = path.join(STORAGE_DIR, username);
  if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
  res.json({ success: true });
});

// Login (respect allowLogin, user enabled)
app.post('/api/login', (req, res) => {
  const settings = loadSettings();
  if (settings.allowLogin === false) return res.status(403).json({ error: 'Login disabled' });
  const { username, password } = req.body;
  const users = loadUsers();
  const user = users[username];
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.enabled === false && user.role !== 'owner') {
    return res.status(403).json({ error: 'User disabled' });
  }
  const token = jwt.sign({ username, role: user.role }, JWT_SECRET);
  res.json({ token, role: user.role });
});

// List files
app.get('/api/files', auth(), (req, res) => {
  const baseDir = req.user.role === 'owner' ? STORAGE_DIR : path.join(STORAGE_DIR, req.user.username);
  const relPath = req.query.path || '';
  const absPath = path.join(baseDir, relPath);
  if (!absPath.startsWith(baseDir)) return res.status(403).json({ error: 'Forbidden' });
  fs.readdir(absPath, { withFileTypes: true }, (err, files) => {
    if (err) return res.status(400).json({ error: 'Cannot read directory' });
    res.json(files.map(f => ({ name: f.name, isDir: f.isDirectory() })));
  });
});

// Read file
app.get('/api/file', auth(), (req, res) => {
  const baseDir = req.user.role === 'owner' ? STORAGE_DIR : path.join(STORAGE_DIR, req.user.username);
  const relPath = req.query.path || '';
  const absPath = path.join(baseDir, relPath);
  if (!absPath.startsWith(baseDir)) return res.status(403).json({ error: 'Forbidden' });
  fs.readFile(absPath, 'utf8', (err, data) => {
    if (err) return res.status(400).json({ error: 'Cannot read file' });
    res.json({ content: data });
  });
});

// Helper: Parse upload limit from settings (supports "100GB", "100MB", "100KB", "100bytes", or number in MB)
function parseUploadLimitMB(val) {
  if (typeof val === 'number') return val;
  if (typeof val !== 'string') return 150;
  let v = val.trim().toLowerCase();
  if (v.endsWith('gb')) return parseFloat(v) * 1024;
  if (v.endsWith('mb')) return parseFloat(v);
  if (v.endsWith('kb')) return parseFloat(v) / 1024;
  if (v.endsWith('bytes')) return parseFloat(v) / (1024 * 1024);
  // Accept just a number as MB
  if (!isNaN(parseFloat(v))) return parseFloat(v);
  return 150;
}

// Upload (respect allowUpload and uploadLimit, not for owner)
app.post('/api/file', auth(), (req, res) => {
  const settings = loadSettings();
  if (settings.allowUpload === false && req.user.role !== 'owner') return res.status(403).json({ error: 'Uploading disabled' });
  // Enforce upload limit for non-owner
  if (req.user.role !== 'owner' && typeof req.body.content === 'string') {
    // Try to detect if the file is base64 or binary string
    let sizeBytes;
    if (/^[A-Za-z0-9+/=\s]+$/.test(req.body.content) && req.body.content.length % 4 === 0) {
      // Looks like base64, try to decode and get real byte length
      try {
        sizeBytes = Buffer.from(req.body.content, 'base64').length;
      } catch {
        sizeBytes = Buffer.byteLength(req.body.content, 'utf8');
      }
    } else {
      sizeBytes = Buffer.byteLength(req.body.content, 'utf8');
    }
    const sizeMB = sizeBytes / (1024 * 1024);
    const sizeKB = sizeBytes / 1024;
    const uploadLimitMB = parseUploadLimitMB(settings.uploadLimit);
    if (uploadLimitMB && sizeMB > uploadLimitMB) {
      return res.status(413).json({
        error: `File too large. Limit is ${uploadLimitMB} MB (${(uploadLimitMB*1024).toFixed(0)} KB).`,
        sizeKB: sizeKB.toFixed(2),
        sizeMB: sizeMB.toFixed(2)
      });
    }
  }
  const baseDir = req.user.role === 'owner' ? STORAGE_DIR : path.join(STORAGE_DIR, req.user.username);
  const relPath = req.body.path || '';
  const absPath = path.join(baseDir, relPath);
  if (!absPath.startsWith(baseDir)) return res.status(403).json({ error: 'Forbidden' });
  fs.writeFile(absPath, req.body.content, err => {
    if (err) return res.status(400).json({ error: 'Cannot write file' });
    res.json({ success: true });
  });
});

// Delete file
app.delete('/api/file', auth(), (req, res) => {
  const baseDir = req.user.role === 'owner' ? STORAGE_DIR : path.join(STORAGE_DIR, req.user.username);
  const relPath = req.body.path || '';
  const absPath = path.join(baseDir, relPath);
  if (!absPath.startsWith(baseDir)) return res.status(403).json({ error: 'Forbidden' });
  fs.rm(absPath, { recursive: true, force: true }, err => {
    if (err) return res.status(400).json({ error: 'Cannot delete' });
    res.json({ success: true });
  });
});

// Set user storage limit (in GB)
app.post('/api/admin/user-limit', auth('owner'), (req, res) => {
  const { username, limitGB } = req.body;
  if (!username || typeof limitGB !== 'number' || limitGB < 0) return res.status(400).json({ error: 'Missing or invalid fields' });
  const users = loadUsers();
  if (!users[username]) return res.status(404).json({ error: 'User not found' });
  users[username].limitGB = limitGB;
  saveUsers(users);
  res.json({ success: true });
});

// User quota endpoint (works with cookie or header auth)
app.get('/api/user/quota', auth(), (req, res) => {
  const users = loadUsers();
  const user = users[req.user.username];
  let limitGB = user && user.limitGB !== undefined ? user.limitGB : (req.user.role === 'owner' ? null : 5);
  let userDir = req.user.role === 'owner' ? STORAGE_DIR : path.join(STORAGE_DIR, req.user.username);
  // Calculate used space
  function getDirSize(dir) {
    let total = 0;
    if (!fs.existsSync(dir)) return 0;
    const files = fs.readdirSync(dir, { withFileTypes: true });
    for (const file of files) {
      const filePath = path.join(dir, file.name);
      if (file.isDirectory()) {
        total += getDirSize(filePath);
      } else {
        try {
          total += fs.statSync(filePath).size;
        } catch {}
      }
    }
    return total;
  }
  const usedBytes = getDirSize(userDir);
  const usedGB = +(usedBytes / (1024 * 1024 * 1024)).toFixed(2);
  res.json({ usedGB, limitGB });
});

// Public endpoint: Get storage usage and limit for a user
app.get('/api/limit/:username', (req, res) => {
  const username = req.params.username;
  if (!username) return res.status(400).json({ error: 'Username required' });
  const users = loadUsers();
  // Case-insensitive username lookup
  const userKey = Object.keys(users).find(u => u.toLowerCase() === username.toLowerCase());
  const user = userKey ? users[userKey] : null;
  if (!user) return res.status(404).json({ error: 'User not found' });
  let limitGB = user.limitGB !== undefined ? user.limitGB : (user.role === 'owner' ? null : 5);
  let userDir = path.resolve(STORAGE_DIR, userKey);

  // Fix: Only count files, not folders, and follow symlinks
  function getDirSize(dir) {
    let total = 0;
    if (!fs.existsSync(dir)) return 0;
    const files = fs.readdirSync(dir, { withFileTypes: true });
    for (const file of files) {
      const filePath = path.join(dir, file.name);
      try {
        const stat = fs.statSync(filePath); // follows symlinks
        if (stat.isDirectory()) {
          total += getDirSize(filePath);
        } else if (stat.isFile()) {
          total += stat.size;
        }
      } catch (e) {
        // skip unreadable files
      }
    }
    return total;
  }

  const usedBytes = getDirSize(userDir);
  const usedGB = +(usedBytes / (1024 * 1024 * 1024)).toFixed(4);
  res.json({ usedGB, limitGB });
});

// Serve user files for preview/download: /api/storage/:username/*
app.get('/api/storage/:username/*', auth(), (req, res) => {
  // Only allow owner or the user themselves
  const requestedUser = req.params.username;
  if (!requestedUser) return res.status(400).json({ error: 'Username required' });
  if (req.user.role !== 'owner' && req.user.username !== requestedUser) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const relPath = req.params[0] || '';
  // Prevent empty path (directory listing)
  if (!relPath) return res.status(400).json({ error: 'File path required' });
  const absPath = path.join(STORAGE_DIR, requestedUser, relPath);
  // Prevent path traversal
  const safeBase = path.join(STORAGE_DIR, requestedUser);
  if (!absPath.startsWith(safeBase)) return res.status(403).json({ error: 'Forbidden' });
  if (!fs.existsSync(absPath) || !fs.statSync(absPath).isFile()) return res.status(404).json({ error: 'Not found' });
  res.sendFile(absPath);
});

// Create owner account if not exists
function ensureOwner() {
  const users = loadUsers();
  if (!users[OWNER_USERNAME]) {
    const hash = bcrypt.hashSync(OWNER_PASSWORD, 10);
    users[OWNER_USERNAME] = { password: hash, role: 'owner' };
    saveUsers(users);
  }
  if (!fs.existsSync(STORAGE_DIR)) fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

// At the bottom, always use HTTP for Express web server
function startServer() {
  const port = settings.port || 3000;
  app.listen(port, () => {
    console.log(`HTTP server running on http://localhost:${port}`);
    console.log('Web server is running in HTTP mode only.');
  });
}

// --- FTP SERVER INTEGRATION ---
const FtpSrv = require('ftp-srv'); // <-- ADD THIS LINE

// Read FTP port from settings.json, fallback to 2121
function getFtpPort() {
  settings = loadSettings(); // reload in case changed
  return settings.ftpPort && Number.isInteger(settings.ftpPort) ? settings.ftpPort : 2121;
}
const FTP_PORT = getFtpPort();
const FTP_URL = `ftp://0.0.0.0:${FTP_PORT}`;

// FTP TLS/SSL support
const HTTPS_KEY = path.join(__dirname, 'certs', 'key.pem');
const HTTPS_CERT = path.join(__dirname, 'certs', 'cert.pem');

function startFtpServer() {
  // TLS options for FTPS
  let tlsOptions = undefined;
  const keyPath = path.join(__dirname, 'certs', 'key.pem');
  const certPath = path.join(__dirname, 'certs', 'cert.pem');
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    tlsOptions = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath)
    };
  }

  const ftpServer = new FtpSrv({
    url: FTP_URL,
    anonymous: false,
    greeting: [settings.welcomeMessage || 'Welcome to the FTP Web Client server!'],
    tls: tlsOptions // Enable FTPS if certs exist
  });

  ftpServer.on('login', async ({ username, password }, resolve, reject) => {
    const users = loadUsers();
    const user = users[username];
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return reject(new Error('Invalid credentials'));
    }
    if (user.enabled === false && user.role !== 'owner') {
      return reject(new Error('User disabled'));
    }
    // Owner: root access, others: only their folder
    let rootDir;
    if (user.role === 'owner') {
      rootDir = STORAGE_DIR;
    } else {
      rootDir = path.join(STORAGE_DIR, username);
      if (!fs.existsSync(rootDir)) fs.mkdirSync(rootDir, { recursive: true });
    }
    // Provide a custom fs with quota enforcement
    const { FileSystem } = require('ftp-srv');
    class QuotaFS extends FileSystem {
      async write(fileName, { append = false } = {}) {
        // Check quota before allowing write
        const limit = getUserStorageLimit(username);
        const used = getUserStorageUsage(username);
        // Estimate new file size (not exact, but good enough)
        let incomingSize = 0;
        try {
          // If file exists, get its size
          const stat = fs.existsSync(fileName) ? fs.statSync(fileName) : null;
          incomingSize = stat ? stat.size : 0;
        } catch {}
        // If over quota, reject
        if (used >= limit) {
          throw new Error('Storage quota exceeded');
        }
        // Wrap the stream to check size as data comes in
        const stream = await super.write(fileName, { append });
        let written = 0;
        stream.on('data', chunk => {
          written += chunk.length;
          if (used + written > limit) {
            stream.destroy(new Error('Storage quota exceeded'));
          }
        });
        return stream;
      }
    }
    resolve({ root: rootDir, fs: QuotaFS });
  });

  ftpServer.listen()
    .then(() => {
      console.log(`FTP server running at ${FTP_URL}`);
    })
    .catch(err => {
      console.error('FTP server failed to start:', err);
    });
}

ensureOwner();
startServer();
startFtpServer();
