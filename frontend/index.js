const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const pool = require('./db');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/views/login.html');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE username=$1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Contraseña incorrecta' });

    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.mfaPending = true;

    if (!user.mfa_secret) {
      const secret = speakeasy.generateSecret({ name: `SIMI-ERP (${user.username})` });
      await pool.query('UPDATE usuarios SET mfa_secret=$1 WHERE id=$2', [secret.base32, user.id]);
      const qr = await qrcode.toDataURL(secret.otpauth_url);
      return res.json({ step: 'setup-mfa', qr, message: 'Escanea el QR y envía el código' });
    }

    res.json({ step: 'verify-mfa', message: 'Ingresa tu código MFA' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

app.post('/verify-mfa', async (req, res) => {
  if (!req.session.mfaPending) return res.status(403).json({ error: 'No autorizado' });
  const { token } = req.body;

  const result = await pool.query('SELECT mfa_secret FROM usuarios WHERE id=$1', [req.session.userId]);
  const secret = result.rows[0].mfa_secret;

  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 1
  });

  if (!verified) return res.status(401).json({ error: 'Código MFA inválido' });

  req.session.mfaPending = false;
  req.session.authenticated = true;

  const jwtToken = jwt.sign(
    { userId: req.session.userId, username: req.session.username },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ message: 'Autenticado correctamente', token: jwtToken });
});

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
}

app.get('/dashboard', authMiddleware, (req, res) => {
  res.json({ message: `Bienvenido ${req.user.username}`, acceso: 'concedido' });
});

app.listen(process.env.PORT, () => {
  console.log(`SIMI ERP corriendo en puerto ${process.env.PORT}`);
});
