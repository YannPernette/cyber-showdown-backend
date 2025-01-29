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
const socketIO = require("socket.io");

// je fais la passerelle avec mon fichier auth dans lequel j'ai mon jeton secret
const { authenticateToken, JWT_SECRET } = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 4000;
const ENV = process.env.NODE_ENV || "development";

// définition du serveur
if (process.env.ENV === "production") {
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
  server = https.createServer(credentials, app);
} else {
  server = http.createServer(app);
}

// gestion Socket.io
const io = socketIO(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true,
  },
});

// Configuration CORS
app.use(cors());

// Parse des données en JSON avec une limite augmentée
app.use(express.json({ limit: "10mb" }));

// Gestion des cookies
app.use(cookieParser());

// Fonction pour générer un ID unique à 6 caractères
function generateUniqueId() {
  return Math.random().toString(36).substring(2, 8).toUpperCase(); // Exemple : '2G64R5'
}

// --------------------------------------------------------------------------------------------------------------------

// Message personnalisé à la racine pour s'assurer que l'API marche
app.get("/", (req, res) => {
  res.send(
    `Bienvenue sur l'API de Cyber Showdown (${
      ENV === "production" ? "HTTPS" : "HTTP"
    })`
  );
});

// Endpoint pour l'inscription
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
            res.status(200).json({ token });
          }
        );
      }
    );
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
app.post("/session/create", authenticateToken, (req, res) => {
  const uniqueId = generateUniqueId();

  db.get("SELECT id FROM sessions WHERE id = ?", [uniqueId], (err, row) => {
    if (err) {
      return res.status(500).json({ message: "Erreur serveur" });
    }
    if (row) {
      // Collision détectée, réessayer avec un autre ID
      tryCreateSession();
    } else {
      // Pas de collision, insérer dans la base de données
      db.run(
        "INSERT INTO sessions (id, status, user1_id, last_activity) VALUES (?, ?, ?, ?)",
        [uniqueId, "open", req.user.id, new Date()],
        function (err) {
          if (err) {
            return res
              .status(500)
              .json({ message: "Erreur lors de la création de la session" });
          }
          res.status(200).json({ sessionId: uniqueId });
        }
      );
    }
  });
});

// Endpoint pour rejoindre une session
app.post("/session/join", authenticateToken, (req, res) => {
  db.get(
    "SELECT * FROM sessions WHERE status = 'open' LIMIT 1",
    (err, session) => {
      if (err || !session) {
        return res.status(404).json({ message: "Aucune session disponible" });
      }

      // Mettre à jour la session pour ajouter le deuxième utilisateur
      db.run(
        "UPDATE sessions SET status = 'full', user2_id = ?, last_activity = ? WHERE id = ?",
        [req.user.id, new Date(), session.id],
        function (err) {
          if (err) {
            return res.status(500).json({
              message: "Erreur lors de l'ajout du joueur à la session",
            });
          }
          res.status(200).json({ sessionId: session.id });
        }
      );
    }
  );
});

// Endpoint pour afficher les informations d'une session
app.get("/session/:id", authenticateToken, (req, res) => {
  const sessionId = req.params.id;

  const query = `
    SELECT 
    sessions.*, 
    user1.*, 
    user2.* 
    FROM sessions
    LEFT JOIN users AS user1 ON sessions.user1_id = user1.id
    LEFT JOIN users AS user2 ON sessions.user2_id = user2.id
    WHERE sessions.id = ?
  `;

  db.get(query, [sessionId], (err, sessionData) => {
    if (err) {
      return res.status(500).json({
        error: "Erreur lors de la récupération des informations de la session",
      });
    }

    if (!sessionData) {
      return res.status(404).json({
        message: "Session non trouvée",
      });
    }

    res.status(200).json(sessionData);
  });
});

// Tâche planifiée pour fermer les sessions inactives
const INACTIVITY_LIMIT = 10 * 60 * 1000; // 10 minutes
setInterval(() => {
  const now = new Date();
  const threshold = new Date(now - INACTIVITY_LIMIT);

  db.run(
    "UPDATE sessions SET status = 'closed' WHERE last_activity < ? AND status != 'closed'",
    [threshold],
    (err) => {
      if (err) {
        console.error(
          "Erreur lors de la fermeture des sessions inactives :",
          err
        );
      } else {
        console.log("Sessions inactive fermée");
      }
    }
  );
}, 60 * 1000); // Vérifie toutes les minutes

// Gestion des connexions Socket.IO
io.on("connection", (socket) => {
  console.log("Utilisateur connecté :", socket.id);

  // Gestion de la déconnexion
  socket.on("disconnect", () => {
    console.log("Utilisateur déconnecté :", socket.id);

    // Fermer la session si elle est liée au socket
    const sessionId = socket.sessionId; // Assurez-vous de stocker l'ID de session
    if (sessionId) {
      db.run(
        "UPDATE sessions SET status = 'closed' WHERE id = ?",
        [sessionId],
        (err) => {
          if (err)
            console.error("Erreur lors de la fermeture de la session :", err);
          else console.log("Session fermée :", sessionId);
        }
      );
    }
  });

  // Gérer l'événement "join-session" pour associer un socket à une session
  socket.on("join-session", (sessionId) => {
    socket.sessionId = sessionId;
    console.log("Utilisateur a rejoint la session :", sessionId);
  });

  // Recevoir des "pings" pour mettre à jour l'activité
  socket.on("activity", (sessionId) => {
    db.run(
      "UPDATE sessions SET last_activity = ? WHERE id = ? AND status != 'closed'",
      [new Date(), sessionId],
      (err) => {
        if (err) {
          console.error("Erreur lors de la mise à jour de l'activité :", err);
        } else {
          console.log("Activité mise à jour pour la session :", sessionId);
        }
      }
    );
  });
});

// --------------------------------------------------------------------------------------------------------------------

// Démarrage du serveur HTTP ou HTTPS
if (ENV === "production") {
  server.listen(PORT, "0.0.0.0", () => {
    console.log(
      "Serveur HTTPS démarré en mode production : https://cyber-showdown-backend.yann-pernette.fr"
    );
  });
} else {
  server.listen(PORT, "0.0.0.0", () => {
    console.log(
      `Serveur HTTP démarré en mode développement : http://localhost:${PORT}`
    );
  });
}
