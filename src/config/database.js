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
        win_condition TEXT NOT NULL,
        title TEXT,
        paragraph_1 TEXT,
        paragraph_2 TEXT
      );
    `);

    // table avec les infos des jeux joués dans une session
    db.run(`
      CREATE TABLE IF NOT EXISTS games_played (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_id INTEGER NOT NULL,
        session_id TEXT NOT NULL
      );
    `);

    // Insérer un jeu seulement s'il n'existe pas déjà
    db.run(`
      INSERT OR IGNORE INTO games (name, time, win_condition, title, paragraph_1, paragraph_2) 
      VALUES ("enable_vpn", "five_seconds", "VPN Activated", "Pourquoi utiliser un VPN ? Protégez votre vie privée en ligne !", 
      "Un VPN (réseau privé virtuel) est un outil simple mais puissant qui permet de protéger vos données personnelles lorsque vous naviguez sur Internet. En utilisant un VPN, votre connexion internet passe par un serveur sécurisé, ce qui rend plus difficile pour les autres, comme les hackers ou les sites web, de suivre vos activités en ligne. Cela signifie que vos informations, comme vos mots de passe ou vos échanges sur les réseaux sociaux, sont mieux protégées.", 
      "De plus, un VPN vous permet d\'accéder à du contenu géo-restreint, comme des séries ou des vidéos disponibles uniquement dans certains pays. Si vous êtes un étudiant qui aime regarder des films ou faire des recherches sur internet, un VPN vous aide à contourner ces limitations et à surfer en toute tranquillité. C\'est une solution facile à mettre en place pour sécuriser vos connexions, surtout quand vous utilisez des réseaux Wi-Fi publics, qui peuvent être risqués.");
`);


    db.run(`
      INSERT OR IGNORE INTO games (name, time, win_condition, title, paragraph_1, paragraph_2) 
      VALUES ("man_in_the_middle", "five_seconds", "Hacked", 
      "L\'attaque de l\'homme du milieu : Un danger caché sur Internet", 
      "L\'attaque de l\'homme du milieu, aussi appelée 'man-in-the-middle' (MITM), est un type de piratage où un attaquant intercepte les communications entre deux parties, comme entre vous et un site web. L\'attaquant peut alors lire, modifier ou même voler les informations échangées, comme des mots de passe ou des numéros de carte bancaire, sans que vous en ayez conscience. Cela peut se produire, par exemple, lorsque vous êtes connecté à un réseau Wi-Fi public non sécurisé.", 
      "Pour vous protéger, il est essentiel de toujours vérifier que le site que vous visitez utilise une connexion sécurisée (indiquée par 'https' dans l\'URL). Utiliser un VPN peut également ajouter une couche de protection en cryptant vos données, rendant ainsi plus difficile pour les attaquants de les intercepter. En étant vigilant et en prenant ces précautions, vous réduisez les risques d\'une attaque de l\'homme du milieu et protégez vos informations personnelles.");
    `);
  });
}

// export de la base de données pour pouvoir l'importer dans app.js
module.exports = db;
