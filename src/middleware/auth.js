// import du module JWT
const jwt = require("jsonwebtoken");

// déclaration d'une constante contenant la clé pour décrypter le JWT
const JWT_SECRET = "super_secret";

function authenticateToken(req, res, next) {
  const authorization = req.headers.authorization;
  // gestion des demandes non authentifiées si la valeur de token n'est pas la bonne
  const token = authorization && authorization.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Vous avez besoin de vous connecter pour accéder à ce service" });
  }
  // erreur si le token n'est plus bon
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Le token n'est plus valide" });
    }
    req.user = user;
    next();
  });
}

module.exports = {
  authenticateToken,
  JWT_SECRET,
};