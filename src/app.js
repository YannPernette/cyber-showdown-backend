// import des modules basiques
const express = require("express");
const https = require("https");
const http = require("http");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const db = require("./config/database");

// je fais la passerelle avec mon fichier auth dans lequel j'ai mon jeton secret
const { authenticateToken, JWT_SECRET } = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 4000;
const ENV = process.env.NODE_ENV || "development";

// Configuration CORS
app.use(cors());

// Parse des données en JSON avec une limite augmentée
app.use(express.json({ limit: "10mb" }));

// Gestion des cookies
app.use(cookieParser());

// --------------------------------------------------------------------------------------------------------------------

// Message personnalisé à la racine pour s'assurer que l'API marche
app.get("/", (req, res) => {
  res.send(
    `Bienvenue sur l'API de Cyber Showdown (${ENV === "production" ? "HTTPS" : "HTTP"})`
  );
});

// Endpoint pour l'inscription
app.post("/auth/register", async (req, res) => {
  const { email, username, password, description, profile_picture } = req.body;

  try {
    db.get("SELECT id FROM users WHERE email = ?", [email], async (err, user) => {
      if (err) return res.status(500).send({ message: "Erreur serveur" });
      if (user) return res.status(400).send({ message: "Email déjà pris" });

      const hashedPassword = await bcrypt.hash(password, 10);

      db.run(
        "INSERT INTO users (email, username, password, description, profile_picture) VALUES (?, ?, ?, ?, ?)",
        [email, username, hashedPassword, description, profile_picture],
        function (err) {
          if (err)
            return res
              .status(500)
              .json({ message: "Erreur lors de la création du compte" });

          const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET, {
            expiresIn: "24h",
          });
          res.status(200).json({ token });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ message: "Erreur serveur", error });
  }
});

// Endpoint pour afficher les infos utilisateur
app.get("/user", authenticateToken, (req, res) => {
  db.get("SELECT * FROM users WHERE id = ?", [req.user.id], (err, userData) => {
    if (err)
      return res.status(500).json({
        error: "Erreur lors de la récupération des infos de l'utilisateur",
      });
    res.json(userData);
  });
});

// Endpoint pour créer une session
app.post("/session/create", (req, res) => {
  const { userId } = req.body;
  db.run(
    "INSERT INTO sessions (status, user1_id, last_activity) VALUES (?, ?, ?)",
    ['open', userId, new Date()],
    function (err) {
      if (err) {
        return res.status(500).json({ message: "Erreur lors de la création de la session" });
      }
      res.status(200).json({ sessionId: this.lastID });
    }
  );
});

// --------------------------------------------------------------------------------------------------------------------

// Démarrage du serveur HTTP ou HTTPS
if (ENV === "production") {
  // Charger les certificats SSL pour HTTPS
  const privateKey = fs.readFileSync(
    "/etc/letsencrypt/live/cyber-showdown-backend.yann-pernette.fr/privkey.pem",
    "utf8"
  );
  const certificate = fs.readFileSync(
    "/etc/letsencrypt/live/cyber-showdown-backend.yann-pernette.fr/cert.pem",
    "utf8"
  );
  const ca = fs.readFileSync(
    "/etc/letsencrypt/live/cyber-showdown-backend.yann-pernette.fr/chain.pem",
    "utf8"
  );

  const credentials = { key: privateKey, cert: certificate, ca: ca };

  https.createServer(credentials, app).listen(PORT, "0.0.0.0", () => {
    console.log(
      `Serveur HTTPS démarré en mode production : https://cyber-showdown-backend.yann-pernette.fr`
    );
  });
} else {
  // Serveur HTTP en développement
  http.createServer(app).listen(PORT, "0.0.0.0", () => {
    console.log(`Serveur HTTP démarré en mode développement : http://localhost:${PORT}`);
  });
}