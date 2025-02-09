// import de sqlite3
const sqlite3 = require("sqlite3").verbose(); // verbose pour obtenir plus d'informations

const db = new sqlite3.Database("./cyber-showdown.db", (err) => {
  if (err) {
    console.error("Erreur de connexion à la base de données : ", err);
  } else {
    console.log("Connecté à la base de données");
    initDatabase();
  }
});

function initDatabase() {
  db.serialize(() => {
    // table avec les infos des utilisateurs
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        description TEXT,
        profile_picture BLOB
      );
    `);

    // table avec les infos des sessions
    db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL DEFAULT 'open',
        user1_id INTEGER,
        user2_id INTEGER,
        user1_lives INTEGER DEFAULT 3,
        user2_lives INTEGER DEFAULT 3,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // table avec les infos des jeux
    db.run(`
      CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        time TEXT NOT NULL,
        win_condition TEXT NOT NULL
      );
    `);

    // Insérer un jeu seulement s'il n'existe pas déjà
    db.run(`
      INSERT OR IGNORE INTO games (name, time, win_condition) VALUES ('enable_vpn', 'five_seconds', 'VPN Activated');
    `);
    db.run(`
      INSERT OR IGNORE INTO games (name, time, win_condition) VALUES ('enable_vpn2', 'five_seconds', 'VPN Activated2');
    `);
  });
}

// export de la base de données pour pouvoir l'importer dans app.js
module.exports = db;