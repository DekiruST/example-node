require("dotenv").config();

const {
  NODE_ENV = "development",
  PORT = 3000,
  SECRET_KEY,
  SECRET_IV,
  ENCRYPTION_METHOD,   
  ECNRYPTION_METHOD,    
} = process.env;

module.exports = {
  env: NODE_ENV,
  port: Number(PORT),
  secret_key: SECRET_KEY,
  secret_iv: SECRET_IV,
  
  encryption_method: ENCRYPTION_METHOD || ECNRYPTION_METHOD || "aes-256-cbc",
};
