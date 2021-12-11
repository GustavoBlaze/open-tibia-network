const { Socket: SocketClient } = require("net");

const client = new SocketClient();

const port = 7171;
const server = "server.tibiarpgbrasil.com";

client.connect(port, server, () => {
  console.log("Conectado!");
});

client.on('data', function(data) {
	console.log('Received: ' + data);
	client.destroy(); // kill client after server's response
});

client.on('close', function() {
	console.log('Connection closed');
});