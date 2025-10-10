const crypto = require("crypto");

function hash(mensaje) {
  const h = crypto.createHash("sha256");
  h.update(String(mensaje));
  return h.digest("hex");
}

module.exports = hash;
