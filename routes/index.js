var express = require('express');
var router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcrypt');

router.use(express.json());

const key = crypto.randomBytes(32); 
const iv  = crypto.randomBytes(16); 


router.get('/', function (req, res) {
  res.render('index', { title: 'Express' });
});

router.post('/encrypt', (req, res) => {
  const data = req.body;
  if (!data || typeof data.mensaje !== 'string') {
    return res.status(400).json({ error: 'mensaje requerido (string)' });
  }

  const algorithm = 'aes-256-cbc';
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encryptedData = cipher.update(data.mensaje, 'utf8', 'hex');
  encryptedData += cipher.final('hex');

  res.json({ 'mensaje-cifrado': encryptedData });
});

router.post('/decrypt', (req, res) => {
  const data = req.body;
  if (!data || typeof data.mensaje !== 'string') {
    return res.status(400).json({ error: 'mensaje cifrado requerido (hex string)' });
  }

  const algorithm = 'aes-256-cbc';
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decryptedData = decipher.update(data.mensaje, 'hex', 'utf8');
  decryptedData += decipher.final('utf8');

  res.json({ 'mensaje-decifrado': decryptedData });
});


router.get('/getkeys', (req, res) => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });


  res.json({
    privateKey,
    publicKey,
  });
});

router.post('/sign-ecc', (req, res) => {
  const data = req.body;
  if (!data || typeof data.mensaje !== 'string' || !data.privateKey) {
    return res.status(400).json({ error: 'mensaje y privateKey (PEM) requeridos' });
  }

  const sign = crypto.createSign('sha256');
  sign.update(data.mensaje);
  sign.end();
  const signatureHex = sign.sign(data.privateKey, 'hex');

  res.json({ 'mensaje-firmado': signatureHex });
});

router.post('/verify-ecc', (req, res) => {
  const data = req.body;
  if (!data || typeof data.mensaje !== 'string' || !data.publicKey || !data.signature) {
    return res.status(400).json({ error: 'mensaje, publicKey (PEM) y signature (hex) requeridos' });
  }

  const verify = crypto.createVerify('sha256');
  verify.update(data.mensaje);
  verify.end();

  const ok = verify.verify(data.publicKey, data.signature, 'hex');
  res.json({ verify: ok });
});


router.post('/encrypt-decrypt', (req, res) => {
  const data = req.body;
  if (!data || typeof data.mensaje !== 'string') {
    return res.status(400).json({ error: 'mensaje requerido' });
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const encryptedData = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(data.mensaje, 'utf8')
  );

  const decryptedData = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    encryptedData
  );

  res.json({
    encrypt: encryptedData.toString('base64'),
    decrypt: decryptedData.toString('utf8'),
    privateKey,
    publicKey,
  });
});

router.get('/getkeys-rsa', (req, res) => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  res.json({ privateKey, publicKey });
});

router.post('/encrypt-rsa', (req, res) => {
  const data = req.body;
  if (!data || typeof data.mensaje !== 'string' || !data.publicKey) {
    return res.status(400).json({ error: 'mensaje y publicKey (PEM) requeridos' });
  }

  const encryptedData = crypto.publicEncrypt(
    {
      key: data.publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(data.mensaje, 'utf8')
  );

  res.json({ 'mensaje-cifrado': encryptedData.toString('base64') });
});

router.post('/decrypt-rsa', (req, res) => {
  const data = req.body;
  if (!data || !data.privateKey || !data.encrypt) {
    return res.status(400).json({ error: 'privateKey (PEM) y encrypt (base64) requeridos' });
  }

  const decryptedData = crypto.privateDecrypt(
    {
      key: data.privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(data.encrypt, 'base64')
  );

  res.json({ mensaje: decryptedData.toString('utf8') });
});

router.post('/firmado-rsa', (req, res) => {
  const data = req.body;
  if (!data || typeof data.mensaje !== 'string' || !data.privateKey) {
    return res.status(400).json({ error: 'mensaje y privateKey (PEM) requeridos' });
  }

  const signature = crypto.sign('sha256', Buffer.from(data.mensaje, 'utf8'), {
    key: data.privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });

  res.json({ 'mensaje-firmado': signature.toString('base64') });
});

router.post('/verify-rsa', (req, res) => {
  const data = req.body;
  if (!data || typeof data.mensaje !== 'string' || !data.publicKey || !data.signature) {
    return res.status(400).json({ error: 'mensaje, publicKey (PEM) y signature (base64) requeridos' });
  }

  const ok = crypto.verify(
    'sha256',
    Buffer.from(data.mensaje, 'utf8'),
    {
      key: data.publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    },
    Buffer.from(data.signature, 'base64')
  );

  res.json({ verify: ok });
});

router.post('/hash', (req, res) => {
  const data = req.body;
  if (!data || typeof data.mensaje !== 'string') {
    return res.status(400).json({ error: 'mensaje requerido' });
  }

  const h = crypto.createHash('sha256');
  h.update(data.mensaje);
  const hashed = h.digest('hex');

  res.json({ hash256: hashed });
});

router.post('/bcrypt', (req, res) => {
  const data = req.body;
  if (!data || typeof data.mensaje !== 'string') {
    return res.status(400).json({ error: 'mensaje requerido' });
  }

  const saltRounds = 12;
  const plainPassword = data.mensaje;

  bcrypt.genSalt(saltRounds, (err, salt) => {
    if (err) return res.status(500).json({ error: 'Error generando salt' });

    bcrypt.hash(plainPassword, salt, (err2, hash) => {
      if (err2) return res.status(500).json({ error: 'Error generando hash' });
      res.json({ hash });
    });
  });
});

module.exports = router;
