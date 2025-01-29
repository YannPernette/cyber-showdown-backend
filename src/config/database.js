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

    db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL DEFAULT 'open',
        user1_id INTEGER,
        user2_id INTEGER,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        timeout_duration INTEGER DEFAULT 30
      );
    `);
  });
}

// export de la base de données pour pouvoir l'importer dans app.js
module.exports = db;