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
let server;
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
  server = https.createServer(credentials, app);
} else {
  server = http.createServer(app);
}

const allowedOrigins = [
  "http://localhost:3000",
  "https://cyber-showdown.yann-pernette.fr",
];

// CORS
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST"],
    credentials: true,
  })
);

// gestion Socket.io
const io = socketIO(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true,
  },
});

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
  const userId = req.user.id;

  // Vérifie si l'utilisateur a accès à la session (en tant que user1 ou user2)
  db.get(
    `
    SELECT s.* 
    FROM sessions s
    WHERE s.id = ? AND (s.user1_id = ? OR s.user2_id = ?)
    `,
    [sessionId, userId, userId],
    (err, session) => {
      if (err) {
        return res
          .status(500)
          .json({ error: "Erreur lors de la récupération de la session" });
      }
      if (!session) {
        return res
          .status(404)
          .json({ error: "Session non trouvée ou accès refusé" });
      }

      // Récupérer les informations des utilisateurs (user1 et user2)
      Promise.all([
        new Promise((resolve, reject) => {
          db.get(
            "SELECT * FROM users WHERE id = ?",
            [session.user1_id],
            (err, user1) => {
              if (err) return reject("Erreur lors de la récupération de user1");
              resolve(user1);
            }
          );
        }),
        new Promise((resolve, reject) => {
          db.get(
            "SELECT * FROM users WHERE id = ?",
            [session.user2_id],
            (err, user2) => {
              if (err) return reject("Erreur lors de la récupération de user2");
              resolve(user2);
            }
          );
        }),
      ])
        .then(([user1, user2]) => {
          // Retourner la réponse consolidée
          res.json({
            ...session,
            user1,
            user2,
          });
        })
        .catch((error) => {
          res.status(500).json({ error });
        });
    }
  );
});

// Endpoint pour sélectionner un jeu de manière aléatoire
let lastGameId = null; // Stocke l'ID du dernier jeu retourné
app.get("/random-game", authenticateToken, (req, res) => {
  let query = "SELECT * FROM games WHERE id != ? ORDER BY RANDOM() LIMIT 1";
  db.get(query, [lastGameId || -1], (err, gameData) => {
    if (err) {
      return res
        .status(500)
        .json({ error: "Erreur lors de la récupération du jeu" });
    }
    if (gameData) {
      lastGameId = gameData.id; // Met à jour l'ID du dernier jeu sélectionné
    }
    res.json(gameData);
  });
});

// Endpoint pour diminuer les vies d'un utilisateur dans une session
app.post("/session/:id/decrease-lives", authenticateToken, (req, res) => {
  const sessionId = req.params.id;
  const userId = req.user.id;

  // Vérifie si l'utilisateur appartient à la session
  db.get(
    `SELECT * FROM sessions WHERE id = ? AND (user1_id = ? OR user2_id = ?)`,
    [sessionId, userId, userId],
    (err, session) => {
      if (err) {
        return res
          .status(500)
          .json({ error: "Erreur lors de la récupération de la session" });
      }
      if (!session) {
        return res
          .status(404)
          .json({ error: "Session non trouvée ou accès refusé" });
      }

      // Déterminer quel utilisateur est en train de jouer
      let columnToUpdate = null;
      let currentLives = null;

      if (session.user1_id === userId) {
        columnToUpdate = "user1_lives";
        currentLives = session.user1_lives;
      } else if (session.user2_id === userId) {
        columnToUpdate = "user2_lives";
        currentLives = session.user2_lives;
      }

      if (columnToUpdate === null) {
        return res.status(403).json({ error: "Accès refusé" });
      }

      // Empêcher les vies négatives
      if (currentLives <= 0) {
        return res.status(400).json({ error: "Aucune vie restante" });
      }

      // Mise à jour des vies
      db.run(
        `UPDATE sessions SET ${columnToUpdate} = ? WHERE id = ?`,
        [currentLives - 1, sessionId],
        function (updateErr) {
          if (updateErr) {
            return res
              .status(500)
              .json({ error: "Erreur lors de la mise à jour des vies" });
          }
          res.json({
            message: "Vie diminuée avec succès",
            [columnToUpdate]: currentLives - 1,
          });
        }
      );
    }
  );
});

// --------------------------------------------------------------------------------------------------------------------

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
        console.log("Session inactive fermée");
      }
    }
  );
}, 60 * 1000); // Vérifie toutes les minutes

// --------------------------------------------------------------------------------------------------------------------

// Stocker les joueurs prêts par session (en dehors du gestionnaire de connexion)
const playersReady = new Map(); // Clé = sessionId, Valeur = Set des joueurs prêts

// Gestion des connexions Socket.IO
io.on("connection", (socket) => {
  console.log("Utilisateur connecté :", socket.id);

  // Gestion de la déconnexion
  socket.on("disconnect", () => {
    console.log("Utilisateur déconnecté :", socket.id);

    // Fermer la session si elle est liée au socket
    const sessionId = socket.sessionId;
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

      // Retirer le joueur de la liste des joueurs prêts
      if (playersReady.has(sessionId)) {
        playersReady.get(sessionId).delete(socket.id);
      }
    }
  });

  // Gérer l'événement "join-session"
  socket.on("join-session", (sessionId) => {
    socket.sessionId = sessionId;
    socket.join(sessionId);

    console.log("Utilisateur a rejoint la session :", sessionId);

    // 🔄 Informer tous les joueurs de cette session qu'un joueur a rejoint
    io.to(sessionId).emit("session-updated");
  });

  socket.on("all-there", (sessionId) => {
    io.to(sessionId).emit("go-game");
  });

  // Recevoir l'état "prêt" d'un joueur
  socket.on("player-ready", (sessionId) => {
    if (!sessionId) return;

    // Initialiser la session si elle n'existe pas encore
    if (!playersReady.has(sessionId)) {
      playersReady.set(sessionId, new Set());
    }

    // Ajouter le joueur dans le set de la session
    const sessionReadyPlayers = playersReady.get(sessionId);
    sessionReadyPlayers.add(socket.id);

    console.log(`Joueur ${socket.id} prêt dans la session ${sessionId}`);
    console.log(`Joueurs prêts : ${sessionReadyPlayers.size}/2`);

    // Vérifier si les deux joueurs sont prêts
    if (sessionReadyPlayers.size === 2) {
      console.log(
        `Tous les joueurs sont prêts dans la session ${sessionId}. Démarrage du jeu.`
      );
      io.to(sessionId).emit("start-countdown");

      // Optionnel : Réinitialiser les joueurs prêts pour éviter des problèmes dans une future partie
      playersReady.delete(sessionId);
    }
  });

  socket.on("start-game", (sessionId) => {
    io.to(sessionId).emit("game-started");
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

  socket.on("decrease-lives", (sessionId) => {
    console.log("-1 vie");
    io.to(sessionId).emit("life-removed");
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
