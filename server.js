/**
 * SmartLive Chat Server v2
 * Socket.io + Token auth + WP integration
 *
 * Install:  npm install
 * Run:      node server.js
 *
 * Env vars:
 *   PORT              (default 3200)
 *   CORS_ORIGIN       (default: your WP domain, NOT *)
 *   WP_REST_URL       (e.g. https://example.com/wp-json/smartlive/v1)
 *   TOKEN_SECRET       (must match SMARTLIVE_TOKEN_SECRET in WP)
 */

const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');

const PORT         = process.env.PORT || 3200;
const CORS_ORIGIN  = process.env.CORS_ORIGIN || 'http://localhost';
const WP_REST_URL  = process.env.WP_REST_URL || 'http://localhost/wp-json/smartlive/v1';
const TOKEN_SECRET = process.env.TOKEN_SECRET || '';

if (!TOKEN_SECRET) {
    console.error('ERROR: TOKEN_SECRET must be set');
    process.exit(1);
}

const SERVER_TOKEN = crypto.createHmac('sha256', TOKEN_SECRET).update('server_push').digest('hex');

// ── HTTP server (also handles internal push from WP) ─────────
const allowedOrigins = CORS_ORIGIN.split(',').map(v => v.trim()).filter(Boolean);

const app = http.createServer((req, res) => {
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-Server-Token');

    if (req.method === 'OPTIONS') {
        res.writeHead(204); res.end();
        return;
    }

    // Health check
    if (req.method === 'GET' && req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('SmartLive Chat OK');
        return;
    }

    // Internal broadcast from WordPress (gift/private_msg confirmed)
    if (req.method === 'POST' && req.url === '/internal/broadcast') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                if (data.serverToken !== SERVER_TOKEN) {
                    res.writeHead(403); res.end('Forbidden'); return;
                }
                const room = 'stream_' + data.streamId;
                io.to(room).emit('message', JSON.stringify(data));
                res.writeHead(200); res.end('OK');
            } catch (e) {
                res.writeHead(400); res.end('Bad request');
            }
        });
        return;
    }

    res.writeHead(404); res.end('Not found');
});

const io = new Server(app, {
    cors: { origin: allowedOrigins, methods: ['GET', 'POST'] },
    transports: ['polling', 'websocket'],
    pingInterval: 25000,
    pingTimeout: 20000,
});

// ── State ────────────────────────────────────────────────────
// rooms: Map<streamId, Set<socketId>>
const rooms = new Map();
// sockets: Map<socketId, { uid, name, sid, isGuest, bc, verified }>
const sockets = new Map();
// muted: Map<streamId, Set<userId>>
const muted = new Map();

const COLORS = ['#d4708f','#c4547a','#a06ab5','#7b9bd4','#6abf96','#d4a057','#e8c179','#b8446a','#22d3ee'];

// ── Token verification ───────────────────────────────────────
function verifyToken(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 2) return null;
        const [json, sig] = parts;
        const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(json).digest('hex');
        if (sig !== expected) return null;
        const payload = JSON.parse(Buffer.from(json, 'base64').toString());
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
        return payload;
    } catch (e) { return null; }
}

// ── Viewer count sync ────────────────────────────────────────
function syncViewerCount(streamId) {
    const room = 'stream_' + streamId;
    const count = rooms.has(room) ? rooms.get(room).size : 0;

    io.to(room).emit('message', JSON.stringify({ type: 'viewer_count', count }));

    // Sync to WordPress DB
    fetch(WP_REST_URL + '/internal/viewer-count', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Server-Token': SERVER_TOKEN },
        body: JSON.stringify({ stream_id: streamId, count }),
    }).catch(() => {});
}

// ── Socket.io ────────────────────────────────────────────────
io.on('connection', (socket) => {

    socket.on('join', (data) => {
        const token = data.token;
        const payload = verifyToken(token);

        if (!payload) {
            socket.emit('message', JSON.stringify({ type: 'error', text: 'Token לא תקין' }));
            socket.disconnect();
            return;
        }

        if (payload.blk) {
            socket.emit('message', JSON.stringify({ type: 'error', text: 'החשבון חסום' }));
            socket.disconnect();
            return;
        }

        const streamId = payload.sid;
        const room = 'stream_' + streamId;

        socket.join(room);

        const info = {
            uid:      payload.uid,
            name:     payload.name,
            sid:      streamId,
            isGuest:  !!payload.guest,
            bc:       !!payload.bc,
            verified: !!payload.ver,
            color:    COLORS[Math.floor(Math.random() * COLORS.length)],
        };
        sockets.set(socket.id, info);

        if (!rooms.has(room)) rooms.set(room, new Set());
        rooms.get(room).add(socket.id);

        syncViewerCount(streamId);

        if (!info.isGuest) {
            io.to(room).emit('message', JSON.stringify({
                type: 'system', text: info.name + ' הצטרף/ה לשידור',
            }));
        }
    });

    // ── Chat message ─────────────────────────────────────────
    socket.on('chat', (data) => {
        const info = sockets.get(socket.id);
        if (!info || info.isGuest || !info.verified) return;

        // Rate limit: 1 message per 2 seconds
        const now = Date.now();
        if (info._lastChat && now - info._lastChat < 2000) return;
        info._lastChat = now;

        // Check muted
        const muteSet = muted.get(info.sid);
        if (muteSet && muteSet.has(info.uid)) return;

        const text = (data.text || '').substring(0, 500).trim();
        if (!text) return;

        const room = 'stream_' + info.sid;
        io.to(room).emit('message', JSON.stringify({
            type: 'chat',
            userId: info.uid,
            displayName: info.name,
            text,
            color: info.color,
            timestamp: now,
        }));
    });

    // ── Moderation (broadcaster + admin) ─────────────────────
    socket.on('moderate', (data) => {
        const info = sockets.get(socket.id);
        if (!info || !info.bc) return;

        if (data.action === 'mute') {
            if (!muted.has(info.sid)) muted.set(info.sid, new Set());
            muted.get(info.sid).add(data.targetUserId);

            const room = 'stream_' + info.sid;
            io.to(room).emit('message', JSON.stringify({
                type: 'system', text: `${data.targetName || 'משתמש'} הושתק`,
            }));
        }

        if (data.action === 'kick') {
            const room = 'stream_' + info.sid;
            for (const [sid, si] of sockets.entries()) {
                if (si.uid === data.targetUserId && si.sid === info.sid) {
                    io.sockets.sockets.get(sid)?.emit('message', JSON.stringify({
                        type: 'system', text: 'הוצאת מהחדר',
                    }));
                    io.sockets.sockets.get(sid)?.disconnect();
                }
            }
        }
    });

    // ── Disconnect ───────────────────────────────────────────
    socket.on('disconnect', () => {
        const info = sockets.get(socket.id);
        sockets.delete(socket.id);

        if (info) {
            const room = 'stream_' + info.sid;
            if (rooms.has(room)) {
                rooms.get(room).delete(socket.id);
                if (rooms.get(room).size === 0) {
                    rooms.delete(room);
                    muted.delete(info.sid);
                } else {
                    syncViewerCount(info.sid);
                }
            }
        }
    });
});

app.listen(PORT, () => {
    console.log(`🔴 SmartLive Chat Server v2 on port ${PORT}`);
});
