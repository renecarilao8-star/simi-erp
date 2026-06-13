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

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  }
  try {
    const exists = await pool.query('SELECT id FROM usuarios WHERE username=$1', [username]);
    if (exists.rows.length > 0) {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO usuarios (username, password_hash) VALUES ($1, $2)', [username, hash]);
    res.json({ message: 'Usuario creado correctamente. Ahora puedes iniciar sesión.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error de servidor' });
  }
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
  req.session.user = req.session.username; // usado por el dashboard

  const jwtToken = jwt.sign(
    { userId: req.session.userId, username: req.session.username },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
  req.session.token = jwtToken;

  res.json({ message: 'Autenticado correctamente', token: jwtToken, redirect: '/dashboard' });
});

// ---------- DASHBOARD ----------
app.get('/dashboard', async (req, res) => {

    if (!req.session.user) {
        return res.redirect('/');
    }

    const productos = await pool.query(
        'SELECT * FROM productos ORDER BY id'
    );

    let filas = '';

    productos.rows.forEach(p => {
        filas += `
        <tr>
            <td>${p.id}</td>
            <td>${p.nombre}</td>
            <td>${p.stock}</td>
            <td>$${p.precio}</td>
        </tr>
        `;
    });

    res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>SIMI ERP</title>

<style>

body{
    font-family: Arial;
    background:#f4f4f4;
    margin:0;
}

header{
    background:#1565c0;
    color:white;
    padding:15px;
}

.container{
    padding:20px;
}

.card{
    background:white;
    padding:20px;
    margin-bottom:20px;
    border-radius:8px;
}

table{
    width:100%;
    border-collapse:collapse;
}

th,td{
    border:1px solid #ddd;
    padding:10px;
}

th{
    background:#1565c0;
    color:white;
}

input{
    padding:10px;
    margin:5px;
}

button{
    padding:10px 15px;
    background:#1565c0;
    color:white;
    border:none;
    cursor:pointer;
}

button:hover{
    background:#0d47a1;
}

</style>

</head>

<body>

<header>
    <h1>Farmacias SIMI ERP</h1>
    <p>Usuario conectado: ${req.session.user}</p>
</header>

<div class="container">

<div class="card">

<h2>Agregar Producto</h2>

<form method="POST" action="/producto">

<input
type="text"
name="nombre"
placeholder="Nombre producto"
required>

<input
type="number"
name="stock"
placeholder="Stock"
required>

<input
type="number"
step="0.01"
name="precio"
placeholder="Precio"
required>

<button type="submit">
Agregar
</button>

</form>

</div>

<div class="card">

<h2>Inventario</h2>

<table>

<tr>
<th>ID</th>
<th>Producto</th>
<th>Stock</th>
<th>Precio</th>
</tr>

${filas}

</table>

</div>

<div class="card">

<form action="/logout" method="GET">
<button>Cerrar Sesión</button>
</form>

</div>

</div>

</body>
</html>
`);
});

// ---------- AGREGAR PRODUCTO ----------
app.post('/producto', async (req, res) => {
  if (!req.session.user) return res.redirect('/');

  const { nombre, stock, precio } = req.body;
  await pool.query(
    'INSERT INTO productos (nombre, stock, precio) VALUES ($1, $2, $3)',
    [nombre, stock, precio]
  );

  res.redirect('/dashboard');
});

// ---------- LOGOUT ----------
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
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

app.listen(process.env.PORT, () => {
  console.log(`SIMI ERP corriendo en puerto ${process.env.PORT}`);
});
