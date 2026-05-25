require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const fetch = require('node-fetch');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;

// Security headers including a strict-ish CSP
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    imgSrc: ["'self'", 'data:', 'https:'],
    connectSrc: ["'self'", 'https:'],
    fontSrc: ["'self'", 'https://fonts.gstatic.com'],
    objectSrc: ["'none'"],
    frameAncestors: ["'none'"],
    upgradeInsecureRequests: []
  }
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: process.env.CORS_ORIGIN || true, credentials: true }));

// Rate limiter
const apiLimiter = rateLimit({ windowMs: 15*60*1000, max: 200 });
app.use('/api/', apiLimiter);

// Sessions
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: (process.env.NODE_ENV==='production'), sameSite: 'lax' }
}));

// Ensure upload dir
const uploadDir = path.resolve(__dirname, process.env.UPLOAD_DIR || '../public/uploads');
fs.mkdirSync(uploadDir, { recursive: true });

// Multer config
const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// DB init
const dbFile = process.env.DB_FILE || './data/resal.db';
const dbDir = path.dirname(dbFile);
fs.mkdirSync(dbDir, { recursive: true });
const db = new sqlite3.Database(dbFile);

// Create tables if not exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      name TEXT,
      password TEXT,
      role TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      cat TEXT,
      emoji TEXT,
      price REAL,
      oldPrice REAL,
      badge TEXT,
      badgeType TEXT,
      rating REAL,
      reviews INTEGER,
      desc TEXT,
      images TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id TEXT,
      customer_name TEXT,
      wilayat TEXT,
      area TEXT,
      phone TEXT,
      items TEXT,
      delivery TEXT,
      deliveryCost REAL,
      total REAL,
      status TEXT,
      payment TEXT,
      proof TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      token_hash TEXT,
      expires_at INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);
});

// Seed admin if missing
db.get('SELECT * FROM users WHERE email=?', ['admin@resal.om'], (err, admin) => {
  if(!admin){
    const hash = bcrypt.hashSync('resal2025', 10);
    db.run('INSERT INTO users (email,name,password,role) VALUES (?,?,?,?)', 
      ['admin@resal.om', 'المدير الرئيسي', hash, 'admin']);
    console.log('Seeded admin account: admin@resal.om / resal2025');
  }
});

// Serve static site
app.use('/', express.static(path.join(__dirname, '..')));
app.use('/uploads', express.static(uploadDir));

// Helpers
function saveImageBuffer(buffer, filename){
  const filepath = path.join(uploadDir, filename);
  fs.writeFileSync(filepath, buffer);
  return Promise.resolve('/uploads/'+filename);
}

// Settings helper
function getSetting(key, callback){
  db.get('SELECT value FROM settings WHERE key=?', [key], (err, row) => {
    callback(err, row ? row.value : null);
  });
}

// Mailer helper that reads settings from DB/env
function createMailer(callback){
  getSetting('smtp_host', (err, host) => {
    host = host || process.env.SMTP_HOST;
    getSetting('smtp_port', (err, portStr) => {
      const port = parseInt(portStr || process.env.SMTP_PORT || 587);
      getSetting('smtp_user', (err, user) => {
        user = user || process.env.SMTP_USER;
        const pass = process.env.SMTP_PASS;
        if(!host || !user) return callback(null);
        callback(nodemailer.createTransport({ host, port, secure: false, auth: { user, pass } }));
      });
    });
  });
}

function sendMail(to, subject, text, html){
  return new Promise((resolve, reject) => {
    createMailer((mailer) => {
      const from = process.env.SMTP_FROM || process.env.SMTP_USER || 'no-reply@example.com';
      if(mailer){
        mailer.sendMail({ from, to, subject, text, html }, (err) => {
          if(err) reject(err);
          else resolve();
        });
      } else {
        console.log('MAIL (no SMTP configured)', { from, to, subject, text });
        resolve();
      }
    });
  });
}

function hashToken(token){ return crypto.createHash('sha256').update(token).digest('hex'); }

// Auth endpoints
app.post('/api/login', (req,res)=>{
  const { email, password } = req.body;
  if(!email||!password) return res.status(400).json({error:'Missing'});
  db.get('SELECT * FROM users WHERE email=?', [email.toLowerCase()], (err, user) => {
    if(!user) return res.status(401).json({error:'Invalid'});
    const ok = bcrypt.compareSync(password, user.password);
    if(!ok) return res.status(401).json({error:'Invalid'});
    req.session.userId = user.id; req.session.role = user.role; req.session.name = user.name;
    res.json({ok:true, name:user.name, role:user.role});
  });
});

app.post('/api/logout',(req,res)=>{ req.session.destroy(()=>res.json({ok:true})); });

// Products
app.get('/api/products',(req,res)=>{
  db.all('SELECT * FROM products ORDER BY id DESC', [], (err, rows) => {
    if(err) return res.status(500).json({error: err.message});
    rows.forEach(r=>{ r.images = r.images?JSON.parse(r.images):[]; });
    res.json(rows);
  });
});

app.post('/api/products', upload.array('images',6), async (req,res)=>{
  if(!req.session.role || (req.session.role!=='admin' && req.session.role!=='moderator')) return res.status(403).json({error:'Forbidden'});
  const { name, cat, price, oldPrice, emoji, badge, desc } = req.body;
  const images = [];
  if(req.files){
    for(const f of req.files){
      const filename = `${Date.now()}-${Math.random().toString(36).slice(2,8)}.jpg`;
      const url = await saveImageBuffer(f.buffer, filename);
      images.push(url);
    }
  }
  const badgeType = badge==='جديد'?'badge-new':badge==='خصم'?'badge-sale':badge==='ساخن'?'badge-hot':'';
  db.run('INSERT INTO products (name,cat,emoji,price,oldPrice,badge,badgeType,rating,reviews,desc,images) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    [name, cat, emoji, parseFloat(price)||0, oldPrice?parseFloat(oldPrice):null, badge, badgeType, 5.0, 0, desc, JSON.stringify(images)],
    function(err) {
      if(err) return res.status(500).json({error: err.message});
      res.json({ok:true});
    });
});

// Password reset request
app.post('/api/password-reset-request', (req,res)=>{
  const { email } = req.body; if(!email) return res.status(400).json({error:'Missing'});
  db.get('SELECT * FROM users WHERE email=?', [email.toLowerCase()], (err, user) => {
    if(!user) return res.json({ok:true});
    const token = crypto.randomBytes(20).toString('hex');
    const tokenHash = hashToken(token);
    const expires = Date.now() + 1000*60*60; // 1 hour
    db.run('INSERT INTO password_resets (user_id,token_hash,expires_at) VALUES (?,?,?)', [user.id, tokenHash, expires], (err) => {
      const link = `${req.protocol}://${req.get('host')}/reset-password.html?token=${token}&email=${encodeURIComponent(user.email)}`;
      sendMail(user.email,'إعادة تعيين كلمة المرور','استخدم الرابط التالي لإعادة التعيين: '+link, `<p>استخدم الرابط التالي لإعادة تعيين كلمة المرور:</p><a href="${link}">${link}</a>`);
      console.log('Password reset link', link);
      res.json({ok:true});
    });
  });
});

// Perform password reset
app.post('/api/password-reset', (req,res)=>{
  const { email, token, password } = req.body; if(!email||!token||!password) return res.status(400).json({error:'Missing'});
  db.get('SELECT * FROM users WHERE email=?', [email.toLowerCase()], (err, user) => {
    if(!user) return res.status(400).json({error:'Invalid'});
    const tokenHash = hashToken(token);
    db.get('SELECT * FROM password_resets WHERE user_id=? AND token_hash=? AND expires_at>?', [user.id, tokenHash, Date.now()], (err, pr) => {
      if(!pr) return res.status(400).json({error:'Invalid or expired'});
      const pwdHash = bcrypt.hashSync(password, 10);
      db.run('UPDATE users SET password=? WHERE id=?', [pwdHash, user.id], (err) => {
        db.run('DELETE FROM password_resets WHERE id=?', [pr.id], (err) => {
          res.json({ok:true});
        });
      });
    });
  });
});

// Upload endpoint (for product images edit)
app.post('/api/uploads', upload.single('image'), async (req,res)=>{
  if(!req.session.role || (req.session.role!=='admin' && req.session.role!=='moderator')) return res.status(403).json({error:'Forbidden'});
  if(!req.file) return res.status(400).json({error:'No file'});
  const filename = `${Date.now()}-${Math.random().toString(36).slice(2,8)}.jpg`;
  const url = await saveImageBuffer(req.file.buffer, filename);
  res.json({url});
});

// Orders
app.post('/api/orders', (req,res)=>{
  const { name, wilayat, area, phone, items, delivery, deliveryCost, total, payment } = req.body;
  if(!name||!wilayat||!area||!phone||!items) return res.status(400).json({error:'Missing'});
  const orderId = 'RS-'+(Math.floor(Date.now()/1000));
  db.run('INSERT INTO orders (order_id,customer_name,wilayat,area,phone,items,delivery,deliveryCost,total,status,payment,proof) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    [orderId, name, wilayat, area, phone, JSON.stringify(items), delivery, deliveryCost, total, 'new', payment, null],
    function(err) {
      if(err) return res.status(500).json({error: err.message});
      // Send notification email (if configured)
      const notifyTo = process.env.NOTIFY_EMAIL || process.env.SMTP_USER;
      if(notifyTo){
        const text = `New order ${orderId} from ${name} - total ${total}`;
        sendMail(notifyTo, `New order ${orderId}`, text, `<p>${text}</p><pre>${JSON.stringify(items,null,2)}</pre>`).catch(e=>console.warn('Mail send failed',e));
      }
      res.json({ok:true,orderId});
    });
});

app.get('/api/orders', (req,res)=>{
  if(!req.session.role) return res.status(403).json({error:'Forbidden'});
  db.all('SELECT * FROM orders ORDER BY id DESC', [], (err, rows) => {
    if(err) return res.status(500).json({error: err.message});
    rows.forEach(r=>{ r.items = r.items?JSON.parse(r.items):[]; });
    res.json(rows);
  });
});

// Settings & Thawani scaffold
app.get('/api/settings',(req,res)=>{
  res.json({thawani: { enabled: process.env.THAWANI_ENABLED==='true', mode: process.env.THAWANI_MODE||'test' }});
});

// Admin-only: update settings in DB (simple key/value)
app.post('/api/settings', (req,res)=>{
  if(!req.session.role || req.session.role!=='admin') return res.status(403).json({error:'Forbidden'});
  const updates = req.body || {};
  Object.keys(updates).forEach(k=>{
    db.run('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)', [k, String(updates[k])]);
  });
  res.json({ok:true});
});

// Thawani payment scaffold
app.post('/api/payments/thawani', async (req,res)=>{
  const { amount, orderId } = req.body; if(!amount) return res.status(400).json({error:'Missing'});
  // If real Thawani keys are provided, create a session; otherwise simulate
  if(process.env.THAWANI_ENABLED==='true' && process.env.THAWANI_SECRET){
    return res.json({ok:true, paymentUrl: 'https://pay.thawani.om/mock', sessionId: 'mock-'+Date.now()});
  }
  // Simulated flow
  res.json({ok:true, paymentUrl: null, sessionId: 'sim-'+Date.now()});
});

// Webhook endpoint placeholder
app.post('/api/webhook/thawani', (req,res)=>{
  console.log('Thawani webhook', req.body);
  res.json({ok:true});
});

app.listen(PORT, ()=>console.log('Server running on',PORT));