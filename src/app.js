// import des modules basiques
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./config/database");
// import pour gérer les chemins de fichiers
const cors = require("cors");

// je fais la passerelle avec mon fichier auth dans lequel j'ai mon jeton secret
const { authenticateToken, JWT_SECRET } = require("./middleware/auth");

const app = express();
const PORT = 4000;

// Configuration CORS
app.use(cors());

// Parse des données en JSON avec une limite augmentée
app.use(express.json({ limit: "10mb" }));

// Gestion des cookies
app.use(cookieParser());

// --------------------------------------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------------------------------------

// définition du port au lancement du server
app.listen(PORT, () => {
  console.log(`http://localhost:${PORT}/`);
});