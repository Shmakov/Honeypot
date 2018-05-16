const EventEmitter = require('events');
const net = require('net');

class CustomSocketServer extends EventEmitter {
	/**
	 * @param {number} port - Socket's Port Number
	 * @param {string} name - Service Name
	 */
	constructor(port, name) {
		super();
		this.port = port;
		this.name = name;
		this.start();
	}
	start () {
		const server = net.createServer((socket) => {
			socket.setEncoding('utf8');
			socket.on('error', (err) => {
				socket.end();
				socket.destroy();
			});
			socket.write('Hi There ' + socket.remoteAddress + ':' + socket.remotePort + '\r\n');
			socket.setTimeout(5000);
			socket.on('timeout', () => {
				this.log(socket);
				socket.end();
				socket.destroy();
			});
			socket.on('data', (data) => {
				this.log(socket, data);
				socket.end();
				socket.destroy();
			});
		});
		server.listen(this.port, () => {});
	}
	log (socket, data) {
		let ip = socket.remoteAddress;
		if (ip && ip.substr(0, 7) === "::ffff:") ip = ip.substr(7);
		let info = {
			'ip': ip,
			'service': this.name,
			'request': 'Connection from ' + ip + ':' + socket.remotePort
		};
		if (data && data.toString().trim().length !== 0) info.request_headers = data.toString();

		this.emit('data', info);
	}
}

module.exports = CustomSocketServer;