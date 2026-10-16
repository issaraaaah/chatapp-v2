const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const { WebSocketServer } = require("ws");
const Database = require("better-sqlite3");

const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, "public");
const EMOJIS = ["👍", "❤️", "😂", "😮", "😢", "🎉"];

// ---------- Base de données (fichier chat.db, ou DB_PATH) ----------
const db = new Database(process.env.DB_PATH || path.join(__dirname, "chat.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT UNIQUE COLLATE NOCASE, hash TEXT, salt TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user TEXT);
CREATE TABLE IF NOT EXISTS rooms(id INTEGER PRIMARY KEY, name TEXT UNIQUE COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, room_id INTEGER, user TEXT, text TEXT, time INTEGER, edited INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS reactions(msg_id INTEGER, user TEXT, emoji TEXT, PRIMARY KEY(msg_id, user, emoji));
`);
["Général", "Détente", "Jeux"].forEach((n) => db.prepare("INSERT OR IGNORE INTO rooms(name) VALUES(?)").run(n));

const roomsList = () => db.prepare("SELECT id, name FROM rooms ORDER BY id").all();
const roomOk = (id) => !!db.prepare("SELECT 1 FROM rooms WHERE id=?").get(id);
function getMsg(id) {
  const r = db.prepare("SELECT * FROM messages WHERE id=?").get(id);
  return r && fmt(r);
}
function fmt(r) {
  const reactions = {};
  for (const x of db.prepare("SELECT user, emoji FROM reactions WHERE msg_id=?").all(r.id))
    (reactions[x.emoji] ||= []).push(x.user);
  return { id: r.id, room: r.room_id, user: r.user, text: r.text, time: r.time, edited: r.edited, reactions };
}

// ---------- Mots de passe (scrypt + sel) ----------
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString("hex");
const checkPw = (pw, u) =>
  crypto.timingSafeEqual(Buffer.from(hashPw(pw, u.salt), "hex"), Buffer.from(u.hash, "hex"));

// ---------- Serveur HTTP + WebSocket ----------
const server = http.createServer((req, res) => {
  const url = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  const file = path.normalize(path.join(PUBLIC, url));
  if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end("Introuvable"); }
    res.writeHead(200, { "Content-Type": file.endsWith(".html") ? "text/html; charset=utf-8" : "text/plain" });
    res.end(data);
  });
});
const wss = new WebSocketServer({ server, maxPayload: 100 * 1024 });

const send = (ws, d) => ws.readyState === 1 && ws.send(JSON.stringify(d));
const all = (d, except) => wss.clients.forEach((c) => c !== except && c.user && send(c, d));
const online = () => [...new Set([...wss.clients].filter((c) => c.user).map((c) => c.user))];

function startSession(ws, name) {
  ws.user = name;
  const token = crypto.randomBytes(24).toString("hex");
  db.prepare("INSERT INTO sessions VALUES(?,?)").run(token, name);
  send(ws, { type: "auth", name, token, rooms: roomsList() });
  all({ type: "users", users: online() });
}

function auth(ws, m) {
  if (m.type === "resume") {
    const s = db.prepare("SELECT user FROM sessions WHERE token=?").get(String(m.token));
    if (!s) return send(ws, { type: "auth_fail" });
    ws.user = s.user;
    send(ws, { type: "auth", name: s.user, token: m.token, rooms: roomsList() });
    return all({ type: "users", users: online() });
  }
  const name = String(m.name || "").trim(), pw = String(m.password || "");
  if (!/^[\p{L}\p{N}_-]{2,20}$/u.test(name)) return send(ws, { type: "error", text: "Pseudo : 2 à 20 caractères (lettres, chiffres, - _)." });
  if (m.type === "register") {
    if (pw.length < 6) return send(ws, { type: "error", text: "Mot de passe : 6 caractères minimum." });
    if (db.prepare("SELECT 1 FROM users WHERE name=?").get(name)) return send(ws, { type: "error", text: "Ce pseudo est déjà pris." });
    const salt = crypto.randomBytes(16).toString("hex");
    db.prepare("INSERT INTO users(name, hash, salt) VALUES(?,?,?)").run(name, hashPw(pw, salt), salt);
    return startSession(ws, name);
  }
  const u = db.prepare("SELECT * FROM users WHERE name=?").get(name);
  if (!u || !checkPw(pw, u)) return send(ws, { type: "error", text: "Pseudo ou mot de passe incorrect." });
  startSession(ws, u.name);
}

wss.on("connection", (ws) => {
  ws.user = null; ws.last = 0;
  ws.on("message", (raw) => {
    try {
      const m = JSON.parse(raw), now = Date.now();
      if (["register", "login", "resume"].includes(m.type)) return auth(ws, m);
      if (!ws.user) return;

      if (m.type === "history" && roomOk(m.room)) {
        const rows = db.prepare("SELECT * FROM messages WHERE room_id=? ORDER BY id DESC LIMIT 50").all(m.room).reverse();
        send(ws, { type: "history", room: m.room, messages: rows.map(fmt) });
      }
      if (m.type === "message") {
        const t = String(m.text || "").trim().slice(0, 1000);
        if (!t || now - ws.last < 300 || !roomOk(m.room)) return;
        ws.last = now;
        const r = db.prepare("INSERT INTO messages(room_id, user, text, time) VALUES(?,?,?,?)").run(m.room, ws.user, t, now);
        all({ type: "message", message: getMsg(r.lastInsertRowid) });
      }
      if (m.type === "edit") {
        const t = String(m.text || "").trim().slice(0, 1000);
        if (!t) return;
        const r = db.prepare("UPDATE messages SET text=?, edited=1 WHERE id=? AND user=?").run(t, m.id, ws.user);
        if (r.changes) all({ type: "update", message: getMsg(m.id) });
      }
      if (m.type === "delete") {
        const row = db.prepare("SELECT room_id FROM messages WHERE id=? AND user=?").get(m.id, ws.user);
        if (!row) return;
        db.prepare("DELETE FROM messages WHERE id=?").run(m.id);
        db.prepare("DELETE FROM reactions WHERE msg_id=?").run(m.id);
        all({ type: "remove", id: m.id, room: row.room_id });
      }
      if (m.type === "react" && EMOJIS.includes(m.emoji) && getMsg(m.id)) {
        const has = db.prepare("SELECT 1 FROM reactions WHERE msg_id=? AND user=? AND emoji=?").get(m.id, ws.user, m.emoji);
        if (has) db.prepare("DELETE FROM reactions WHERE msg_id=? AND user=? AND emoji=?").run(m.id, ws.user, m.emoji);
        else db.prepare("INSERT INTO reactions VALUES(?,?,?)").run(m.id, ws.user, m.emoji);
        all({ type: "update", message: getMsg(m.id) });
      }
      if (m.type === "room_new") {
        const n = String(m.name || "").trim().slice(0, 20);
        if (n.length < 2) return;
        db.prepare("INSERT OR IGNORE INTO rooms(name) VALUES(?)").run(n);
        all({ type: "rooms", rooms: roomsList() });
      }
      if (m.type === "typing") all({ type: "typing", user: ws.user, room: m.room }, ws);
    } catch (e) { console.error(e.message); }
  });
  ws.on("close", () => ws.user && all({ type: "users", users: online() }));
});

server.listen(PORT, () => console.log(`Chat disponible sur http://localhost:${PORT}`));