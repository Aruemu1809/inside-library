const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const AUTH_PASS = "inside-2025"; // 認証パスコード（好きに変えてOK）

const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false,
}));

// 簡易ユーザーデータ
const USERS_FILE = 'users.json';
let users = fs.existsSync(USERS_FILE) ? JSON.parse(fs.readFileSync(USERS_FILE)) : {};

// ファイルアップロード設定
const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    const filename = Date.now() + '-' + file.originalname;
    cb(null, filename);
  }
});
const upload = multer({ storage });

// ミドルウェア：認証チェック
function isAuthenticated(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

// ルーティング
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  const type = req.query.type || 'core';
  res.render('login', { type });
});

app.post('/login', async (req, res) => {
  const { id, password } = req.body;
  const user = users[id];
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.userId = id;
    res.redirect('/dashboard');
  } else {
    res.render('login', { type: 'core' }); // ←ここ！typeを忘れず渡す！
  }
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  const { id, password, displayName, group, authpass } = req.body;

  if (authpass !== AUTH_PASS) {
    return res.send('認証パスコードが間違っています');
  }

  if (id.length < 4) {
    return res.send('ユーザーIDは4文字以上にしてください');
  }

  if (password.length < 6) {
    return res.send('パスワードは6文字以上にしてください');
  }

  if (users[id]) return res.send('すでに登録されてるIDです');

  const hashed = await bcrypt.hash(password, 10);
  const joinedAt = new Date().toISOString();
  users[id] = { password: hashed, displayName, group, joinedAt };

  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  res.redirect('/login?type=' + group);
});

app.get('/dashboard', isAuthenticated, (req, res) => {
  const files = fs.readdirSync('uploads/').map(filename => {
    const stat = fs.statSync(`uploads/${filename}`);
    return {
      name: filename,
      uploader: {
        displayName: users[req.session.userId].displayName,
        group: users[req.session.userId].group
      },
      date: stat.ctime
    };
  });

  res.render('dashboard', {
    user: users[req.session.userId],
    files
  });
});

app.post('/upload', isAuthenticated, upload.single('file'), (req, res) => {
  res.redirect('/dashboard');
});

app.listen(PORT, () => console.log(`http://localhost:${PORT} で起動中`));