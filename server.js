require('dotenv').config(); // Charge les variables d'environnement depuis .env
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');
const multer = require('multer');
const axios = require('axios');
const http = require('http');
const https = require('https');
const { Server } = require("socket.io");
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const express = require('express');
const app = express();

const PORT = 3000;

// --- Certificat SSL chargé depuis des fichiers (ne jamais mettre les clés dans le code) ---
const server = https.createServer({
    key: fs.readFileSync(path.join(__dirname, 'ssl', 'key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'ssl', 'cert.pem'))
}, app);

const io = new Server(server);
const activeScans = new Set(); // Suivi des scans en cours par utilisateur

const dbPath = path.resolve(__dirname, 'arc_database.db');
const db = new sqlite3.Database(dbPath);

// Configuration du serveur
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json()); // Permet de gérer les requêtes JSON pour l'API
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'"],
            "script-src-attr": ["'unsafe-inline'"],  // ← Ligne ajoutée
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "blob:"],
            "connect-src": ["'self'", "ws:", "wss:"]
        }
    }
}));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    message: "Trop de tentatives de connexion. Réessayez dans 15 minutes.",
    skip: (req) => {
        // Ne pas limiter localhost (développement/tests)
        const ip = req.ip || req.socket.remoteAddress;
        return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
    }
});
app.use('/login', loginLimiter);

app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_pas_du_tout_secure_pour_dev',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000, // Session d'1 heure
              httpOnly: true, // Empêche le vol de session via JS (XSS)
              secure: true,  // HTTPS activé
              sameSite: 'lax' // Protection contre le CSRF
            }
}));

// Configuration de l'upload de fichiers (Multer)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir);
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'));
    }
});
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // Limite à 5Mo
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|pdf|txt|csv|docx/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) return cb(null, true);
        cb(new Error("Type de fichier non autorisé ! Seuls les images, PDF et documents sont permis."));
    }
});

// --- MIDDLEWARE DE SÉCURITÉ (Le Douanier) ---
// Ce code s'exécute avant de servir les fichiers
app.use((req, res, next) => {
    const currentPath = req.path.replace(/\/$/, '') || '/'; // Renommé et normalisé
    
    // --- 1. RESSOURCES PUBLIQUES (Toujours autorisées) ---
    const publicExtensions = ['.css', '.js', '.jpg', '.png', '.ico', '.svg'];
    const publicPages = ['/', '/login.html', '/creation_de_compte.html', '/mot_de_passe_oublie.html', '/login', '/register', '/logout', '/api/scan/webhook'];

    // --- SÉCURITÉ : Interdiction d'accès aux fichiers sensibles du projet ---
    const forbiddenFiles = ['.env', '.db', '.log', 'server.js', 'scanner_service.js', 'package.json', 'node_modules', '.git'];
    if (forbiddenFiles.some(file => currentPath.toLowerCase().endsWith(file.toLowerCase()))) {
        return res.status(403).send("Accès interdit : Fichier système protégé.");
    }

    // Si le chemin est public ou est une ressource statique, on laisse passer
    if ((currentPath === '/' || publicPages.includes(currentPath) || publicExtensions.some(ext => currentPath.endsWith(ext))) && !currentPath.startsWith('/uploads/')) {
        return next();
    }

    // --- 2. PROTECTION DES DOSSIERS SENSIBLES ---
    if (currentPath.startsWith('/reports/')) {
        return res.status(403).send("Accès interdit. Utilisez le bouton de téléchargement.");
    }

    // --- 3. VÉRIFICATION DE L'AUTHENTIFICATION ---
    if (!req.session.userId) {
        if (currentPath.startsWith('/api/')) {
            return res.status(401).json({ error: "Session expirée ou invalide. Veuillez vous reconnecter." });
        }
        return res.redirect('/login.html');
    }

    // --- 4. CONTRÔLE D'ACCÈS PAR RÔLE (RBAC) ---
    const role = req.session.role;

    if ((currentPath === '/mainadmin.html' || currentPath === '/gestion_utilisateurs.html') && role !== 'admin') {
        return res.redirect('/home');
    }
    if (currentPath === '/mainit.html' && role !== 'it') {
        return res.redirect('/home');
    }
    next();
});

app.use(express.static(__dirname)); // Sert les fichiers (CSS, Login, Images) seulement si le "douanier" laisse passer

// Initialisation de la Base de Données
db.serialize(() => {
    // Configuration pour éviter les verrouillages (SQLITE_BUSY)
    db.run("PRAGMA busy_timeout = 4000", (err) => {
        if (err) console.error("Info DB: Impossible de définir le timeout (ce n'est pas critique)");
    }); 
    db.run("PRAGMA journal_mode = WAL", (err) => {
        if (err) console.error("Info DB: Impossible de mettre le mode WAL (ce n'est pas critique)");
    });

    // Création de la table utilisateurs
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
    )`);

    // Création de la table tickets (pour les scans/conversations)
    db.run(`CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        subject TEXT,
        target_ip TEXT,
        status TEXT DEFAULT 'ouvert',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Création de la table messages (pour le chat dans les tickets)
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER,
        sender_id INTEGER,
        content TEXT,
        is_ai_analysis BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Mise à jour de la table messages pour supporter les fichiers (Migration simple)
    db.run("ALTER TABLE messages ADD COLUMN type TEXT DEFAULT 'text'", (err) => { if (err && !err.message.includes('duplicate column name')) console.error("Migration Error (type):", err.message); });
    db.run("ALTER TABLE messages ADD COLUMN attachment_url TEXT", (err) => { if (err && !err.message.includes('duplicate column name')) console.error("Migration Error (attachment_url):", err.message); });
    db.run("ALTER TABLE messages ADD COLUMN attachment_name TEXT", (err) => { if (err && !err.message.includes('duplicate column name')) console.error("Migration Error (attachment_name):", err.message); });
    db.run("ALTER TABLE tickets ADD COLUMN target_ip TEXT", (err) => { if (err && !err.message.includes('duplicate column name')) console.error("Migration Error (target_ip):", err.message); });
    db.run("ALTER TABLE messages ADD COLUMN is_ai_analysis BOOLEAN DEFAULT 0", (err) => { if (err && !err.message.includes('duplicate column name')) console.error("Migration Error (is_ai_analysis):", err.message); });
    db.run("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0", (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error("Migration Error (failed_login_attempts):", err.message);
        }
    });

    db.run("ALTER TABLE users ADD COLUMN lockout_level INTEGER DEFAULT 0", (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error("Migration Error (lockout_level):", err.message);
        }
    });

    db.run("ALTER TABLE users ADD COLUMN locked_until INTEGER DEFAULT NULL", (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error("Migration Error (locked_until):", err.message);
        }
    });

db.run("ALTER TABLE users ADD COLUMN locked_by_admin INTEGER DEFAULT 0", (err) => {
    if (err && !err.message.includes('duplicate column name')) {
        console.error("Migration Error (locked_by_admin):", err.message);
    }
});
    // Création de la table logs (Historique complet)
    db.run(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        user_name TEXT,
        action TEXT,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Création d'un compte Admin par défaut si la base est vide
    db.get("SELECT count(*) as count FROM users", [], (err, row) => {
        if (row && row.count === 0) {
            const hash = bcrypt.hashSync("admin123", 10);
            db.run("INSERT INTO users (fullname, email, password, role) VALUES (?, ?, ?, ?)", 
                ['Administrateur Système', 'admin@arc.sn', hash, 'admin']);
            console.log("--- INITIALISATION ---");
            console.log("Compte Admin créé par défaut :");
            console.log("Email: admin@arc.sn");
            console.log("Mdp: admin123");
            console.log("----------------------");
        }
    });
});

// Fonction utilitaire pour ajouter un log
function addLog(userId, userName, action, details) {
    db.run("INSERT INTO logs (user_id, user_name, action, details) VALUES (?, ?, ?, ?)", 
        [userId, userName, action, details], (err) => { if(err) console.error("Log Error:", err); });
}

// --- ROUTES ---

// Redirection de la racine vers la page de connexion (Pour accès simplifié par IP)
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

// 1. Inscription (Création de compte)
app.post('/register', async (req, res) => {
    const { fullname, email, password, confirm_password } = req.body;
    const role = 'client'; // Le rôle est toujours forcé côté serveur

    // Vérification simple
    if (password !== confirm_password) {
        return res.send('<script>alert("Les mots de passe ne correspondent pas."); window.history.back();</script>');
    }

    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.send('<script>alert("Le mot de passe doit contenir au moins 8 caractères et au moins un chiffre."); window.history.back();</script>');
    }

    try {
        // Hachage du mot de passe (ne jamais stocker en clair)
        const hash = await bcrypt.hash(password, 10);

        // Insertion en base
        db.run("INSERT INTO users (fullname, email, password, role) VALUES (?, ?, ?, ?)", 
            [fullname, email, hash, role], 
            (err) => {
                if (err) {
                    // Erreur (ex: email déjà pris)
                    return res.send('<script>alert("Erreur: Cet email est peut-être déjà utilisé."); window.history.back();</script>');
                }
                // Succès -> Redirection vers le login
                // On loggue l'inscription (pas d'ID utilisateur connecté ici, donc null)
                addLog(null, "Système", "INSCRIPTION", `Nouvel utilisateur inscrit : ${email} (${role})`);
                res.redirect('/creation_de_compte.html?status=success');
            }
        );
    } catch (e) {
        res.redirect('/creation de compte.html');
    }
});

// 2. Connexion
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const now = Date.now();

    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (err || !user) {
            addLog(null, "Système", "LOGIN_FAILED", `Tentative de connexion avec email inconnu : ${email} (IP: ${userIp})`);
            return res.redirect('/login.html?error=invalid');
        }

        if (user.locked_by_admin === 1) {
            addLog(user.id, user.fullname, "LOGIN_BLOCKED", `Connexion refusée : compte bloqué par un administrateur (IP: ${userIp})`);
            return res.redirect('/login.html?error=locked_admin');
        }

        if (user.locked_until && now < user.locked_until) {
            const remainingSeconds = Math.ceil((user.locked_until - now) / 1000);
            addLog(user.id, user.fullname, "LOGIN_BLOCKED", `Connexion refusée : compte temporairement bloqué encore ${remainingSeconds} secondes (IP: ${userIp})`);
            return res.redirect(`/login.html?error=locked&remaining=${remainingSeconds}`);
        }

        const match = await bcrypt.compare(password, user.password);

        if (match) {
            db.run(
                "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
                [user.id]
            );

            req.session.userId = user.id;
            req.session.role = user.role;
            req.session.fullname = user.fullname;

            addLog(user.id, user.fullname, "CONNEXION", `Connexion réussie (IP: ${userIp})`);

            req.session.save(() => {
                if (user.role === 'admin') res.redirect('/mainadmin.html');
                else if (user.role === 'it') res.redirect('/mainit.html');
                else res.redirect('/main.html');
            });

        } else {
            const failedAttempts = (user.failed_login_attempts || 0) + 1;
            let lockoutLevel = user.lockout_level || 0;

            addLog(user.id, user.fullname, "LOGIN_FAILED", `Mot de passe incorrect. Tentative ${failedAttempts}/3 (IP: ${userIp})`);

            if (failedAttempts >= 3) {
                lockoutLevel += 1;

                // Niveau 1 = blocage 2 min, Niveau 2 = blocage 1h
                // Niveau 3+ = blocage définitif par admin (locked_by_admin)
                if (lockoutLevel >= 3) {
                    db.run(
                        "UPDATE users SET failed_login_attempts = 0, lockout_level = ?, locked_until = NULL, locked_by_admin = 1 WHERE id = ?",
                        [lockoutLevel, user.id]
                    );
                    addLog(
                        user.id,
                        user.fullname,
                        "ACCOUNT_LOCKED",
                        `Compte bloqué DÉFINITIVEMENT après récidive post-blocage 1h. Déblocage admin requis. (IP: ${userIp})`
                    );
                    return res.redirect('/login.html?error=locked_admin');
                }

                let lockDurationMs;
                if (lockoutLevel === 1) {
                    lockDurationMs = 2 * 60 * 1000;       // 2 minutes
                } else {
                    lockDurationMs = 60 * 60 * 1000;      // 1 heure
                }

                const lockedUntil = now + lockDurationMs;

                db.run(
                    "UPDATE users SET failed_login_attempts = 0, lockout_level = ?, locked_until = ? WHERE id = ?",
                    [lockoutLevel, lockedUntil, user.id]
                );

                addLog(
                    user.id,
                    user.fullname,
                    "ACCOUNT_LOCKED",
                    `Compte bloqué automatiquement après 3 échecs. Durée : ${lockoutLevel === 1 ? '2 minutes' : '1 heure'} (IP: ${userIp})`
                );

                return res.redirect('/login.html?error=locked');
            }

            db.run(
                "UPDATE users SET failed_login_attempts = ? WHERE id = ?",
                [failedAttempts, user.id]
            );

            const remainingAttempts = 3 - failedAttempts;
            return res.redirect(`/login.html?error=invalid&attempts=${remainingAttempts}`);
        }
    });
});
// 3. Déconnexion
app.get('/logout', (req, res) => {
    if(req.session.userId) {
        const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        addLog(req.session.userId, req.session.fullname || "Inconnu", "DECONNEXION", `Déconnexion de l'utilisateur (IP: ${userIp})`);
    }
    
    req.session.destroy();
    res.redirect('/login.html');
});

// Route de redirection intelligente pour le bouton "Accueil"
app.get('/home', (req, res) => {
    if (!req.session.userId) return res.redirect('/login.html');

    const role = req.session.role;
    if (role === 'admin') {
        res.redirect('/mainadmin.html');
    } else if (role === 'it') {
        res.redirect('/mainit.html');
    } else {
        res.redirect('/main.html');
    }
});

// --- API GESTION UTILISATEURS (Pour l'admin) ---

// Récupérer la liste des utilisateurs
app.get('/api/users', (req, res) => {
    // Sécurité : seul l'admin peut voir ça
    if (req.session.role !== 'admin') return res.status(403).json({ error: "Accès refusé" });

    db.all("SELECT id, fullname, email, role, failed_login_attempts, lockout_level, locked_until, locked_by_admin FROM users WHERE email != ?", ['admin@arc.sn'], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        // On ajoute l'information de scan en cours à chaque utilisateur
        const usersWithScanStatus = rows.map(user => ({
            ...user,
            is_scanning: activeScans.has(user.id)
        }));
        res.json(usersWithScanStatus);
    });
});

// Modifier le rôle d'un utilisateur
app.post('/api/users/update-role', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: "Accès refusé" });

    const { id, newRole } = req.body;
    db.run("UPDATE users SET role = ? WHERE id = ? AND email != ?", [newRole, id, 'admin@arc.sn'], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        addLog(req.session.userId, req.session.fullname, "ADMIN_ROLE", `Rôle de l'utilisateur ID ${id} changé en ${newRole}`);
        res.json({ success: true });
    });
});

// Supprimer un utilisateur
app.post('/api/users/delete', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: "Accès refusé" });

    const { id } = req.body;
    // On empêche l'admin de se supprimer lui-même par sécurité
    if (id == req.session.userId) return res.status(400).json({ error: "Impossible de se supprimer soi-même" });

    db.run("DELETE FROM users WHERE id = ? AND email != ?", [id, 'admin@arc.sn'], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        addLog(req.session.userId, req.session.fullname, "ADMIN_DELETE", `Suppression de l'utilisateur ID ${id}`);
        res.json({ success: true });
    });
});
// Débloquer un utilisateur (réinitialise le verrouillage)
app.post('/api/users/unlock', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: "Accès refusé" });

    const { id } = req.body;
    db.run(
        "UPDATE users SET failed_login_attempts = 0, lockout_level = 0, locked_until = NULL, locked_by_admin = 0 WHERE id = ?",
        [id],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            addLog(req.session.userId, req.session.fullname, "ADMIN_UNLOCK", `Compte de l'utilisateur ID ${id} débloqué manuellement`);
            res.json({ success: true });
        }
    );
});



// Changer le mot de passe (Depuis settings.html)
app.post('/api/user/change-password', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: "Non connecté" });

    const { currentPassword, newPassword } = req.body;

    db.get("SELECT password FROM users WHERE id = ?", [req.session.userId], async (err, row) => {
        if (err || !row) return res.status(500).json({ error: "Erreur interne" });

        const match = await bcrypt.compare(currentPassword, row.password);
        if (!match) return res.status(400).json({ error: "Le mot de passe actuel est incorrect." });

        const newHash = await bcrypt.hash(newPassword, 10);
        db.run("UPDATE users SET password = ? WHERE id = ?", [newHash, req.session.userId], (err) => {
            if (err) {
                console.error("Erreur DB update password:", err.message);
                return res.status(500).json({ error: "Erreur technique : Base de données occupée. Réessayez." });
            }
            addLog(req.session.userId, req.session.fullname, "SECURITE", "Mot de passe modifié");
            res.json({ success: true });
        });
    });
});

// Récupérer les infos de l'utilisateur connecté (Pour la page paramètres)
app.get('/api/user/me', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: "Non connecté" });

    db.get("SELECT id, fullname, email, role FROM users WHERE id = ?", [req.session.userId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row);
    });
});

// --- API SCAN & CONVERSATIONS ---

// Vérifier si l'utilisateur a un scan en cours
app.get('/api/scan/status', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: "Non connecté" });
    res.json({ scanning: activeScans.has(req.session.userId) });
});

function isValidTargetIp(ip) {
    if (!net.isIPv4(ip) && !net.isIPv6(ip)) return false;
    // Bloquer loopback et plages privées (SSRF)
    const parts = ip.split('.').map(Number);
    if (parts[0] === 127) return false;
    if (parts[0] === 10) return false;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
    if (parts[0] === 192 && parts[1] === 168) return false;
    if (parts[0] === 169 && parts[1] === 254) return false;
    if (ip === '0.0.0.0' || ip === '::1') return false;
    return true;
}

// Lancer un scan (Crée un ticket)
app.post('/api/scan/start', (req, res) => {
    console.log(`[DEBUG] Route /api/scan/start appelée par l'utilisateur ID: ${req.session?.userId}`);
    if (!req.session.userId) return res.status(401).json({ error: "Session expirée ou invalide. Veuillez vous reconnecter." });

    const userId = req.session.userId;

    if (activeScans.has(userId)) {
        return res.status(429).json({ error: "Un scan est déjà en cours pour votre compte. Veuillez attendre la fin du précédent." });
    }

    let targetIp = req.body.targetIp;

    if (!targetIp) {
        let clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        if (clientIp.substr(0, 7) == "::ffff:") clientIp = clientIp.substr(7);
        targetIp = clientIp === '::1' ? '127.0.0.1' : clientIp;
    }

    if (!isValidTargetIp(targetIp)) {
        return res.status(400).json({ error: "Adresse IP invalide ou non autorisée." });
    }

    activeScans.add(userId);
    
    // On crée d'abord le ticket pour avoir un ID unique (synchronisation parfaite Logs/Fichier/Ticket)
    db.run("INSERT INTO tickets (user_id, subject, target_ip, status) VALUES (?, ?, ?, ?)", 
        [userId, 'Initialisation...', targetIp, 'ouvert'],
        function(err) {
            if (err) {
                activeScans.delete(userId);
                return res.status(500).json({ error: err.message });
            }
            
            const ticketId = this.lastID;
            const subject = `Rapport de Scan #${ticketId}`; // On utilise l'ID unique
            
            // Mise à jour immédiate du sujet
            db.run("UPDATE tickets SET status = 'prise en charge' WHERE id = ?", [ticketId]);
            db.run("UPDATE tickets SET subject = ? WHERE id = ?", [subject, ticketId]);
            addLog(userId, req.session.fullname, "SCAN", `Lancement du scan #${ticketId}`);
            
            // Création du dossier 'reports' s'il n'existe pas
            const reportsDir = path.join(__dirname, 'reports');
            try {
                if (!fs.existsSync(reportsDir)) {
                    console.log(`[SERVER] Création du répertoire de rapports: ${reportsDir}`);
                    fs.mkdirSync(reportsDir, { recursive: true });
                }
            } catch (fsError) {
                console.error("Erreur création dossier:", fsError);
                return res.status(500).json({ error: "Erreur serveur lors de la préparation du rapport" });
            }

            // Réponse immédiate au client pour éviter le timeout, le scan se fera en arrière-plan
            res.json({ success: true, ticketId: ticketId });

            // Appel au serveur de scan externe
            const scannerServerUrl = 'http://127.0.0.1:4000/run-scan';

            // Webhook interne en HTTP (port dédié) pour éviter les soucis de certificat auto-signé
            const callbackUrl = `http://127.0.0.1:${PORT}/api/scan/webhook`;

            axios.post(
                scannerServerUrl,
                {
                   ticketId: ticketId,
                   targetIp: targetIp,
                    callbackUrl: callbackUrl
                },
               {
                   headers: {
                       'x-scanner-api-key': process.env.SCANNER_API_KEY
                   },
               }
            )
            .then(response => {
                console.log(`[SERVER] Scan délégué au serveur de scan pour ticket ${ticketId}. Réponse: ${response.status}`);
            })
            .catch(async e => {
                console.error(`[SERVER] Erreur d'appel au serveur de scan pour ticket ${ticketId}:`, e.message);
                activeScans.delete(userId);
                // Mettre à jour le statut du ticket en erreur et ajouter un message
                db.run("UPDATE tickets SET status = 'erreur' WHERE id = ?", [ticketId]); // Le statut reste 'erreur' en cas d'échec de connexion au scanner
                db.run("INSERT INTO messages (ticket_id, sender_id, content) VALUES (?, 0, ?)", [ticketId, `Échec de la connexion au serveur de scan: ${e.message}. Vérifiez que le service est lancé et que l'IP est correcte.`], (msgErr) => { if (msgErr) console.error("Erreur msg systeme", msgErr); });
            });
        }
    );
});

app.post('/api/scan/webhook', (req, res) => {
    const apiKey = req.headers['x-scanner-api-key'];
    if (!apiKey || apiKey !== process.env.SCANNER_API_KEY) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    const { ticketId, type, content, status } = req.body;

    if (type === 'status_message') { // Nouveau type pour les messages de statut
        db.run("INSERT INTO messages (ticket_id, sender_id, content) VALUES (?, 0, ?)", [ticketId, content]);
        io.emit('new_message', { ticketId, content, sender_id: 0, fullname: 'Système ARC' });
    }
    else if (type === 'log') { // Ancien type, peut être fusionné avec status_message si le contenu est toujours un message
        db.run("INSERT INTO messages (ticket_id, sender_id, content) VALUES (?, 0, ?)", [ticketId, content]);
        io.emit('new_message', { ticketId, content, sender_id: 0, fullname: 'Système ARC' });
    }
    else if (type === 'file_content') {
        const reportsDir = path.join(__dirname, 'reports');
        const filePath = path.join(reportsDir, `scan_report_${ticketId}.txt`);
        console.log(`[WEBHOOK] Tentative d'écriture du rapport pour le ticket ${ticketId} à: ${filePath}`);
        fs.writeFile(filePath, content, (err) => {
            if (err) {
                console.error(`[WEBHOOK] Erreur écriture rapport pour le ticket ${ticketId}:`, err);
            } else {
                console.log(`[WEBHOOK] Rapport pour le ticket ${ticketId} écrit avec succès.`);
                // Mettre à jour le sujet du ticket pour indiquer la disponibilité du rapport final
                const newSubject = `Rapport Final - ${ticketId}`;
                db.run("UPDATE tickets SET subject = ? WHERE id = ?", [newSubject, ticketId]);
                io.emit('ticket_update', { ticketId, subject: newSubject });

                // Optionnel : Insérer l'analyse IA directement dans le chat
                db.run("INSERT INTO messages (ticket_id, sender_id, content, is_ai_analysis) VALUES (?, 0, ?, 1)", [ticketId, "L'analyse IA est terminée. Consultez le rapport pour plus de détails."]);
                io.emit('new_message', { ticketId, content: "Analyse IA disponible.", sender_id: 0, is_ai_analysis: 1 });
            }
        });
    }
    else if (type === 'file_available') { // Nouveau type pour indiquer que le fichier est prêt
        db.run("INSERT INTO messages (ticket_id, sender_id, content) VALUES (?, 0, ?)", [ticketId, "Rapport de scan disponible en téléchargement."]);
        io.emit('new_message', { ticketId, content: "Rapport de scan disponible en téléchargement.", sender_id: 0 });
    }
    else if (type === 'status_update') { // Nouvelle gestion des mises à jour de statut
        db.run("UPDATE tickets SET status = ? WHERE id = ?", [status, ticketId], (err) => {
            if (err) console.error(`[WEBHOOK] Erreur mise à jour statut ticket ${ticketId}:`, err);

            // Libération de l'utilisateur si le scan est terminé (succès ou erreur)
            if (status === 'ouvert' || status === 'erreur') {
                db.get("SELECT user_id FROM tickets WHERE id = ?", [ticketId], (err, row) => {
                    if (row) activeScans.delete(row.user_id);
                });
            }

            io.emit('ticket_update', { ticketId, status });
        });
    }

    res.sendStatus(200);
});

app.get('/api/get-my-ip', (req, res) => {

    if (!req.session.userId) {
        return res.status(401).json({
            error: "Session expirée ou invalide. Veuillez vous reconnecter."
        });
    }

    let ip =
        req.headers['x-forwarded-for'] ||
        req.socket.remoteAddress;

    if (ip && ip.startsWith('::ffff:')) {
        ip = ip.substring(7);
    }

    if (ip === '::1') {
        ip = '127.0.0.1';
    }

    res.json({
        ip: ip
    });
});

// Récupérer les tickets (Filtrage par rôle)
app.get('/api/tickets', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: "Session expirée ou invalide. Veuillez vous reconnecter." });

    let query = "SELECT tickets.*, users.fullname as user_name FROM tickets JOIN users ON tickets.user_id = users.id";
    let params = [];

    // Si c'est un client, il ne voit que SES tickets
    if (req.session.role === 'client') {
        query += " WHERE tickets.user_id = ?";
        params.push(req.session.userId);
    }
    // Admin et IT voient TOUT (pas de WHERE supplémentaire)

    query += " ORDER BY tickets.created_at DESC";

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Récupérer les messages d'un ticket spécifique
app.get('/api/tickets/:id/messages', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: "Session expirée ou invalide. Veuillez vous reconnecter." });
    const ticketId = req.params.id;

    // Vérification de sécurité : le client a-t-il le droit de voir ce ticket ?
    db.get("SELECT user_id FROM tickets WHERE id = ?", [ticketId], (err, ticket) => {
        if (err || !ticket) return res.status(404).json({ error: "Ticket introuvable" });

        if (req.session.role === 'client' && ticket.user_id !== req.session.userId) {
            return res.status(403).json({ error: "Accès interdit à ce ticket" });
        }

        // Si autorisé, on récupère les messages
        db.all(`SELECT messages.*, users.fullname, users.role
                FROM messages
                LEFT JOIN users ON messages.sender_id = users.id 
                WHERE ticket_id = ? ORDER BY created_at ASC`, [ticketId], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    });
});

// Envoyer un message dans un ticket
app.post('/api/tickets/:id/messages', (req, res) => {
    upload.single('attachment')(req, res, (err) => {
        if (err instanceof multer.MulterError || err) {
            return res.status(400).json({ error: err.message });
        }
        if (!req.session.userId) return res.status(401).json({ error: "Session expirée ou invalide." });

    const ticketId = req.params.id;
    const content = req.body.content || "";

    let type = 'text';
    let attachmentUrl = null;
    let attachmentName = null;

    if (req.file) {
        const mime = req.file.mimetype;
        type = mime.startsWith('image/') ? 'image' : mime.startsWith('video/') ? 'video' : 'file';
        attachmentUrl = '/uploads/' + req.file.filename;
        attachmentName = req.file.originalname;
    }

    // Note: Idéalement, on revérifie les droits ici comme pour le GET
    db.run("INSERT INTO messages (ticket_id, sender_id, content, type, attachment_url, attachment_name) VALUES (?, ?, ?, ?, ?, ?)",
        [ticketId, req.session.userId, content, type, attachmentUrl, attachmentName], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        io.emit('new_message', { ticketId, sender_id: req.session.userId, content, type, attachment_url: attachmentUrl, attachment_name: attachmentName, fullname: req.session.fullname });
        addLog(req.session.userId, req.session.fullname, "MESSAGE", `Message envoyé sur le ticket #${ticketId} (${type})`);
        res.json({ success: true });
    });
    });
});

// Modifier un message
app.put('/api/messages/:id', (req, res) => { // Correction: 'path' est déjà défini
    if (!req.session.userId) return res.status(401).json({ error: "Session expirée ou invalide. Veuillez vous reconnecter." });
    const messageId = req.params.id;
    const { content } = req.body;

    db.get("SELECT sender_id, ticket_id, content FROM messages WHERE id = ?", [messageId], (err, msg) => {
        if (err || !msg) return res.status(404).json({ error: "Message introuvable" });

        if (msg.sender_id !== req.session.userId) {
             return res.status(403).json({ error: "Vous ne pouvez modifier que vos propres messages" });
        }

        db.run("UPDATE messages SET content = ? WHERE id = ?", [content, messageId], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            addLog(req.session.userId, req.session.fullname, "MESSAGE_EDIT", `Message #${messageId} modifié dans le ticket #${msg.ticket_id}. Ancien: "${msg.content}" -> Nouveau: "${content}"`);
            res.json({ success: true });
        });
    });
});

// Supprimer un message
app.delete('/api/messages/:id', (req, res) => { // Correction: 'path' est déjà défini
    if (!req.session.userId) return res.status(401).json({ error: "Session expirée ou invalide. Veuillez vous reconnecter." });
    const messageId = req.params.id;

    db.get("SELECT sender_id, ticket_id, content FROM messages WHERE id = ?", [messageId], (err, msg) => {
        if (err || !msg) return res.status(404).json({ error: "Message introuvable" });

        // Autoriser l'auteur ou l'admin
        if (msg.sender_id !== req.session.userId && req.session.role !== 'admin') {
             return res.status(403).json({ error: "Action non autorisée" });
        }

        db.run("DELETE FROM messages WHERE id = ?", [messageId], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            addLog(req.session.userId, req.session.fullname, "MESSAGE_DELETE", `Message #${messageId} supprimé du ticket #${msg.ticket_id}. Contenu supprimé : ${msg.content}`);
            res.json({ success: true });
        });
    });
});

// Changer le statut d'un ticket (Admin/IT seulement)
app.post('/api/tickets/:id/status', (req, res) => { // Correction: 'path' est déjà défini
    if (!req.session.userId) return res.status(401).json({ error: "Non connecté" });

    // Vérification des rôles
    if (req.session.role !== 'admin' && req.session.role !== 'it') {
        return res.status(403).json({ error: "Accès refusé" });
    }

    const ticketId = req.params.id;
    const { status } = req.body;

    db.get("SELECT status FROM tickets WHERE id = ?", [ticketId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: "Ticket introuvable" });

        const oldStatus = row.status;
        db.run("UPDATE tickets SET status = ? WHERE id = ?", [status, ticketId], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            addLog(req.session.userId, req.session.fullname, "STATUS", `Statut du ticket #${ticketId} changé de '${oldStatus}' à '${status}'`);
            res.json({ success: true });
        });
    });
});

// Supprimer un ticket
app.delete('/api/tickets/:id', (req, res) => { // Correction: 'path' est déjà défini
    if (!req.session.userId) return res.status(401).json({ error: "Non connecté" });
    const ticketId = req.params.id;

    db.get("SELECT user_id, subject FROM tickets WHERE id = ?", [ticketId], (err, ticket) => {
        if (err || !ticket) return res.status(404).json({ error: "Ticket introuvable" });

        // Vérification des droits : Admin ou Propriétaire du ticket
        if (req.session.role !== 'admin' && ticket.user_id !== req.session.userId) {
            return res.status(403).json({ error: "Accès refusé" });
        }

        // Suppression des messages associés
        db.run("DELETE FROM messages WHERE ticket_id = ?", [ticketId]);

        // Suppression du fichier rapport associé s'il existe
        const reportPath = path.join(__dirname, 'reports', `scan_report_${ticketId}.txt`);
        fs.unlink(reportPath, (err) => { /* On ignore l'erreur si le fichier n'existe pas */ });

        // Suppression du ticket
        db.run("DELETE FROM tickets WHERE id = ?", [ticketId], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            addLog(req.session.userId, req.session.fullname, "TICKET_DELETE", `Suppression de : ${ticket.subject}`);
            res.json({ success: true });
        });
    });
});

// Suppression en masse de tickets
app.post('/api/tickets/delete-bulk', (req, res) => { // Correction: 'path' est déjà défini
    if (!req.session.userId) return res.status(401).json({ error: "Non connecté" });
    const { ids } = req.body;

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: "Aucune sélection" });
    }

    // Préparer la requête pour vérifier les droits sur ces IDs
    const placeholders = ids.map(() => '?').join(',');
    const query = `SELECT id, user_id, subject FROM tickets WHERE id IN (${placeholders})`;

    db.all(query, ids, (err, tickets) => {
        if (err) return res.status(500).json({ error: err.message });

        // Filtrer : Admin peut tout supprimer, Client seulement les siens
        const validTickets = tickets.filter(t => req.session.role === 'admin' || t.user_id === req.session.userId);
        const validIds = validTickets.map(t => t.id);

        if (validIds.length === 0) return res.json({ success: true, count: 0 }); // Rien à faire

        // Suppression des fichiers physiques
        validTickets.forEach(t => {
            const reportPath = path.join(__dirname, 'reports', `scan_report_${t.id}.txt`);
            fs.unlink(reportPath, () => {}); // On ignore les erreurs si fichier absent
        });

        const validPlaceholders = validIds.map(() => '?').join(',');

        // Suppression en base (Messages puis Tickets)
        db.run(`DELETE FROM messages WHERE ticket_id IN (${validPlaceholders})`, validIds);
        db.run(`DELETE FROM tickets WHERE id IN (${validPlaceholders})`, validIds, (err) => {
            if (err) return res.status(500).json({ error: err.message });

            const deletedSubjects = validTickets.map(t => t.subject).join(', ');
            addLog(req.session.userId, req.session.fullname, "BULK_DELETE", `Suppression groupée de ${validIds.length} tickets: ${deletedSubjects}`);
            res.json({ success: true, count: validIds.length });
        });
    });
});

// Télécharger le rapport
app.get('/api/reports/:id/download', (req, res) => { // Correction: 'path' est déjà défini
    if (!req.session.userId) return res.status(401).send("Non connecté");
    const ticketId = req.params.id;

    db.get("SELECT user_id, subject FROM tickets WHERE id = ?", [ticketId], (err, ticket) => {
        if (err || !ticket) return res.status(404).send("Ticket introuvable");

        // Vérification des droits
        if (req.session.role === 'client' && ticket.user_id !== req.session.userId) { // Correction: Utiliser req.session.userId
            return res.status(403).send("Accès refusé");
        }

        const reportPath = path.join(__dirname, 'reports', `scan_report_${ticketId}.txt`);
        console.log(`[DOWNLOAD] Tentative de téléchargement du rapport depuis: ${reportPath}`);
        if (fs.existsSync(reportPath)) {
            addLog(req.session.userId, req.session.fullname, "DOWNLOAD", `Téléchargement de : ${ticket.subject}`);
            res.download(reportPath, `Rapport_Scan_${ticketId}.txt`); // Nom de fichier plus joli pour l'utilisateur
        } else {
            res.status(404).send("Fichier de rapport non trouvé sur le serveur.");
        }
    });
});

// Récupérer les LOGS (Admin/IT seulement)
app.get('/api/logs', (req, res) => { // Correction: 'path' est déjà défini
    if (!req.session.userId || (req.session.role !== 'admin' && req.session.role !== 'it')) {
        return res.status(403).json({ error: "Accès refusé" });
    }
    db.all("SELECT * FROM logs ORDER BY created_at DESC", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Télécharger les logs en CSV
app.get('/api/logs/download', (req, res) => { // Correction: 'path' est déjà défini
    if (!req.session.userId || (req.session.role !== 'admin' && req.session.role !== 'it')) {
        return res.status(403).send("Accès refusé");
    }

    db.all("SELECT * FROM logs ORDER BY created_at DESC", [], (err, rows) => {
        if (err) return res.status(500).send("Erreur base de données");

        // Génération du CSV
        const header = "ID,Date,Utilisateur,Action,Détails\n";
        const csvContent = rows.map(row => {
            const cleanDetails = row.details ? `"${row.details.replace(/"/g, '""').replace(/\n/g, ' ')}"` : '""';
            const cleanUser = row.user_name ? `"${row.user_name.replace(/"/g, '""')}"` : '"Système"';
            return `${row.id},"${row.created_at}",${cleanUser},"${row.action}",${cleanDetails}`;
        }).join("\n");

        addLog(req.session.userId, req.session.fullname, "DOWNLOAD_LOGS", "Export des logs CSV");
        res.header('Content-Type', 'text/csv; charset=utf-8');
        res.attachment(`logs_arc_${Date.now()}.csv`);
        res.send("\ufeff" + header + csvContent);
    });
});

// Vider les logs (Admin uniquement)
app.delete('/api/logs', (req, res) => { // Correction: 'path' est déjà défini
    if (!req.session.userId || req.session.role !== 'admin') {
        return res.status(403).json({ error: "Accès refusé. Réservé aux administrateurs." });
    }
    db.run("DELETE FROM logs", (err) => {
        if (err) return res.status(500).json({ error: err.message });
        addLog(req.session.userId, req.session.fullname, "CLEAR_LOGS", "Historique des logs effacé par l'admin");
        res.json({ success: true });
    });
});

server.listen(PORT, '0.0.0.0', () => {
    const interfaces = os.networkInterfaces();
    const addresses = [];
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                addresses.push({ name, address: iface.address });
            }
        }
    }
    console.log(`--- SERVEUR ARC DÉMARRÉ (HTTPS) ---`);
    console.log(`⚠️  Certificat auto-signé : acceptez l'avertissement navigateur.`);
    console.log(`Local  : https://localhost:${PORT}/login.html`);
    addresses.forEach(addr => console.log(`Réseau : https://${addr.address}:${PORT}/`));
    console.log(`------------------------------------`);
});