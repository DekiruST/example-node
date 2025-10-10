const crypto = require("crypto");
const { secret_key, secret_iv, encryption_method } = require("../config/config");

if (!secret_key || !secret_iv || !encryption_method) {
  throw new Error("secret_key, secret_iv y encryption_method son requeridos");
}


const key = crypto.createHash("sha512").update(String(secret_key)).digest().subarray(0, 32);
const iv  = crypto.createHash("sha512").update(String(secret_iv)).digest().subarray(0, 16);

function encryptData(data) {
  const cipher = crypto.createCipheriv(encryption_method, key, iv);
  const encrypted = Buffer.concat([cipher.update(String(data), "utf8"), cipher.final()]);
  return encrypted.toString("base64"); 
}

function decryptData(encryptedBase64) {
  const encrypted = Buffer.from(String(encryptedBase64), "base64");
  const decipher = crypto.createDecipheriv(encryption_method, key, iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString("utf8");
}

module.exports = { encryptData, decryptData };
