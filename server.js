const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');

const PORT         = process.env.PORT || 3200;
const CORS_ORIGIN  = process.env.CORS_ORIGIN || '*';
const WP_REST_URL  = process.env.WP_REST_URL || 'http://localhost/wp-json/smartlive/v1';
const TOKEN_SECRET = process.env.TOKEN_SECRET || '';

if (!TOKEN_SECRET) { console.error('ERROR: TOKEN_SECRET must be set'); process.exit(1); }

const SERVER_TOKEN = crypto.createHmac('sha256', TOKEN_SECRET).update('server_push').digest('hex');
const ALLOWED = CORS_ORIGIN === '*' ? null : CORS_ORIGIN.split(',').map(s => s.trim());

function setCors(req, res) {
    const origin = req.headers.origin;
    if (!origin) return;
    if (ALLOWED === null || ALLOWED.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-Server-Token');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
}

const app = http.createServer((req, res) => {
    setCors(req, res);

    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
    if (req.method === 'GET' && req.url === '/') { res.writeHead(200); res.end('SmartLive Chat OK'); return; }

    if (req.method === 'POST' && req.url === '/internal/broadcast') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                if (data.serverToken !== SERVER_TOKEN) { res.writeHead(403); res.end('Forbidden'); return; }
                io.to('stream_' + data.streamId).emit('message', JSON.stringify(data));
                res.writeHead(200); res.end('OK');
            } catch (e) { res.writeHead(400); res.end('Bad request'); }
        });
        return;
    }
});

const io = new Server(app, {
    cors: {
        origin: ALLOWED || '*',
        methods: ['GET', 'POST'],
        credentials: true,
    },
    transports: ['polling', 'websocket'],
    allowEIO3: true,
});

const rooms = new Map(), sockets = new Map(), muted = new Map();
const COLORS = ['#d4708f','#c4547a','#a06ab5','#7b9bd4','#6abf96','#d4a057','#e8c179','#b8446a','#22d3ee'];

function verifyToken(token) {
    try {
        const parts = token.split('.'); if (parts.length !== 2) return null;
        const [json, sig] = parts;
        const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(json).digest('hex');
        if (sig !== expected) return null;
        const payload = JSON.parse(Buffer.from(json, 'base64').toString());
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
        return payload;
    } catch (e) { return null; }
}

function syncViewerCount(streamId) {
    const room = 'stream_' + streamId;
    const count = rooms.has(room) ? rooms.get(room).size : 0;
    io.to(room).emit('message', JSON.stringify({ type: 'viewer_count', count }));
    fetch(WP_REST_URL + '/internal/viewer-count', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Server-Token': SERVER_TOKEN },
        body: JSON.stringify({ stream_id: streamId, count }),
    }).catch(() => {});
}

io.on('connection', (socket) => {
    socket.on('join', (data) => {
        const payload = verifyToken(data.token);
        if (!payload) { socket.emit('message', JSON.stringify({ type: 'error', text: 'Token לא תקין' })); socket.disconnect(); return; }
        if (payload.blk) { socket.emit('message', JSON.stringify({ type: 'error', text: 'החשבון חסום' })); socket.disconnect(); return; }
        const streamId = payload.sid, room = 'stream_' + streamId;
        socket.join(room);
        const info = { uid: payload.uid, name: payload.name, sid: streamId, isGuest: !!payload.guest, bc: !!payload.bc, verified: !!payload.ver, color: COLORS[Math.floor(Math.random() * COLORS.length)] };
        sockets.set(socket.id, info);
        if (!rooms.has(room)) rooms.set(room, new Set());
        rooms.get(room).add(socket.id);
        syncViewerCount(streamId);
        if (!info.isGuest) io.to(room).emit('message', JSON.stringify({ type: 'system', text: info.name + ' הצטרף/ה לשידור' }));
    });

    socket.on('chat', (data) => {
        const info = sockets.get(socket.id);
        if (!info || info.isGuest || !info.verified) return;
        const now = Date.now();
        if (info._lastChat && now - info._lastChat < 2000) return;
        info._lastChat = now;
        const muteSet = muted.get(info.sid);
        if (muteSet && muteSet.has(info.uid)) return;
        const text = (data.text || '').substring(0, 500).trim();
        if (!text) return;
        io.to('stream_' + info.sid).emit('message', JSON.stringify({ type: 'chat', userId: info.uid, displayName: info.name, text, color: info.color, timestamp: now }));
    });

    socket.on('moderate', (data) => {
        const info = sockets.get(socket.id);
        if (!info || !info.bc) return;
        if (data.action === 'mute') {
            if (!muted.has(info.sid)) muted.set(info.sid, new Set());
            muted.get(info.sid).add(data.targetUserId);
            io.to('stream_' + info.sid).emit('message', JSON.stringify({ type: 'system', text: (data.targetName || 'משתמש') + ' הושתק' }));
        }
        if (data.action === 'kick') {
            for (const [sid, si] of sockets.entries()) {
                if (si.uid === data.targetUserId && si.sid === info.sid) {
                    io.sockets.sockets.get(sid)?.emit('message', JSON.stringify({ type: 'system', text: 'הוצאת מהחדר' }));
                    io.sockets.sockets.get(sid)?.disconnect();
                }
            }
        }
    });

    socket.on('disconnect', () => {
        const info = sockets.get(socket.id);
        sockets.delete(socket.id);
        if (info) {
            const room = 'stream_' + info.sid;
            if (rooms.has(room)) {
                rooms.get(room).delete(socket.id);
                if (rooms.get(room).size === 0) { rooms.delete(room); muted.delete(info.sid); }
                else syncViewerCount(info.sid);
            }
        }
    });
});

app.listen(PORT, () => { console.log('SmartLive Chat Server v2 on port ' + PORT); });
