let ws;
const logDiv = document.getElementById('log');
const topicInput = document.getElementById('topicInput');
const msgInput = document.getElementById('msgInput');

// 1. Inisialisasi Koneksi
// Pakai ws:// jika testing lokal, wss:// jika sudah pakai TLS
ws = new WebSocket("ws://localhost:8080"); 

ws.onopen = () => {
    addLog("Connected to Halmos Server!", "info");
};

ws.onmessage = (event) => {
    try {
        const data = JSON.parse(event.data);
        // Tampilkan pesan yang datang
        addLog(`Incoming: ${event.data}`, "msg");
    } catch (e) {
        addLog(`Raw Data: ${event.data}`, "msg");
    }
};

ws.onclose = () => {
    addLog("Connection lost. Server might be down or kicked you.", "err");
};

// 2. Fungsi Subscribe (Daftar ke Topik)
function subscribe() {
    const topic = topicInput.value;
    if (!topic) return alert("Isi topik dulu!");

    const subPacket = {
        "header": {
            "type": "SUB",      // Sesuai ws_cfg.keys.action
            "dst": topic,       // Sesuai ws_cfg.keys.to
            "app_id": "GLOBAL"  // Sesuai ws_cfg.keys.app
        },
        "payload": {}
    };

    ws.send(JSON.stringify(subPacket));
    addLog(`Subscribed to: ${topic}`, "info");
}

// 3. Fungsi Publish (Kirim Pesan ke Semua Orang di Topik)
function publish() {
    const topic = topicInput.value;
    const message = msgInput.value;
    if (!topic || !message) return alert("Isi topik & pesan!");

    const pubPacket = {
        "header": {
            "type": "PUB",
            "dst": topic,
            "app_id": "GLOBAL"
        },
        "payload": {
            "text": message,
            "sender": "User_" + Math.floor(Math.random() * 1000)
        }
    };

    ws.send(JSON.stringify(pubPacket));
    msgInput.value = ""; // Clear input
}

function addLog(text, type) {
    const p = document.createElement('div');
    p.className = type;
    p.innerText = `[${new Date().toLocaleTimeString()}] ${text}`;
    logDiv.appendChild(p);
    logDiv.scrollTop = logDiv.scrollHeight;
}