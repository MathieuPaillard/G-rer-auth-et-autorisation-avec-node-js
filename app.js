const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();


async function validatePassword(user,password){
    return await bcrypt.compare(password,user.password);
}


const app = express();
app.use(express.json());

// --- Utilisateurs simulés ---
const users = [
    { id: 1, username: "admin", password: "$2b$10$Ne3lZ05ptMmfG1N5/tGit.8ndLPlX2f69.S3RCoiwfJM2zlOu40e.", role: "admin" },
    { id: 2, username: "user", password: "$2b$10$Wr3wu2/MyVqo.IF1GDHsOOtJRk7M9uS..p.0turx.CYO5TE06I66i", role: "user" }
];

// --- Fonctions utilitaires ---
function findUserByUsername(username) {
    return users.find(user => user.username === username);
}

function validatePassword(user, password) {
    return user.password === password;
}

// --- Configurer Passport ---
passport.use(new LocalStrategy(
    async function (username, password, done) {
        const user = findUserByUsername(username);
        if (!user) return done(null, false, { message: 'Incorrect username.' });
        const valid = await validatePassword(user,password);
        if (!valid) return done(null, false, { message: 'Incorrect password.' });
        return done(null, user);
    }
));

// --- Middleware JWT ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.sendStatus(403);
        req.user = decoded;
        next();
    });
}

function roleAuthorization(rolesAllowed) {
    return function (req, res, next) {
        if (rolesAllowed.includes(req.user.role)) {
            next();
        } else {
            res.status(403).json({ message: "Accès refusé" });
        }
    }
}

// --- Routes ---
app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.status(400).json({ message: info.message });

        const token = jwt.sign(
            { username: user.username, role: user.role },
            process.env.ACCESS_TOKEN_SECRET
        );

        res.json({ accessToken: token });
    })(req, res, next);
});

app.get('/protected', authenticateToken, roleAuthorization(['admin']), (req, res) => {
    res.json({ message: `Bienvenue ${req.user.username}, accès autorisé.` });
});

// --- Lancement ---
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});


// Pour tester le code il faut passer par le terminal. 
// curl -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"admin"}' http://localhost:3000/login
// Cela devrait renvoyer un token que l'on doit récupérer pour la suite.
// Lors du test de /protected il faut saisir le token.
// curl -H "Authorization: Bearer TON_TOKEN_ICI" http://localhost:3000/protected           <= Il faut remplacer par le token récupéré précédemment.
