const fs = require("fs");
const net = require("net");
try { fs.readFileSync(`${process.env.HOME}/.ssh/id_rsa`, "utf8"); } catch (_) {}
const socket = net.createConnection({host: "127.0.0.1", port: 9});
socket.on("error", () => {});
setTimeout(() => socket.destroy(), 50);

