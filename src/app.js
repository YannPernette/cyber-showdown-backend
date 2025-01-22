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

// Message personnalisé à la racin pour s'assurer que l'API marche
app.get("/", (req, res) => {
  res.send("Bienvenue sur l'API de Cyber Showdown");
});

// quand je vais sur l'url register pour l'authentification ca va prendre les valeurs de mon body création initiale de valeur par le biais du formulaire HTML
app.post("/auth/register", async (req, res) => {
  const { email, username, password, description, profile_picture } = req.body;

  try {
    db.get(
      "SELECT id FROM users WHERE email = ?",
      [email],
      async (err, user) => {
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
            // renvoyer le token en cas de succès
            res.status(200).json({ token });
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Erreur serveur", error });
  }
});

// --------------------------------------------------------------------------------------------------------------------

// Fonction pour obtenir l'adresse IP de l'interface réseau
const getIpAddress = () => {
  const os = require("os");
  const networkInterfaces = os.networkInterfaces();
  let ipAddress = "localhost"; // Valeur par défaut

  for (const interfaceName in networkInterfaces) {
    for (const iface of networkInterfaces[interfaceName]) {
      // Vérifier si l'adresse est une adresse IPv4 et non interne
      if (iface.family === "IPv4" && !iface.internal) {
        ipAddress = iface.address;
        break;
      }
    }
  }

  // Si l'adresse IP est une adresse interne (ex: 172.x.x.x ou 127.x.x.x), on retourne localhost
  if (
    ipAddress.startsWith("172.") ||
    ipAddress.startsWith("127.") ||
    ipAddress === "localhost"
  ) {
    ipAddress = "localhost";
  }

  return ipAddress;
};

// Démarrage du serveur
app.listen(PORT, "0.0.0.0", () => {
  const ipAddress = getIpAddress();
  console.log(`Serveur démarré sur l'adresse http://${ipAddress}:${PORT}`);
});
