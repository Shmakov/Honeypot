"use strict";

const config = require('./../config');
const helper = require('./../lib/helper');
const EventEmitter = require('events');
const fs = require('fs');
const net = require('net');
const FtpSrv = require('ftp-srv');
const ssh2 = require('ssh2');
const chalk = require('chalk');

class SocketServer extends EventEmitter {
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

	start() {
		throw new Error('You have to implement the `start` method!');
	}

	onError(err) {
		if (err.code === 'EADDRINUSE') console.log(chalk.bgYellow.bold('Warning:') + ' Cannot start `' + this.name + '` service on port ' + this.port + '. Error Code: EADDRINUSE, Address already in use.');
		else if (err.code === 'EACCES') console.log(chalk.bgYellow.bold('Warning:') + ' Cannot start `' + this.name + '` service on port ' + this.port + '. Error Code: EACCES, Permission Denied.');
		else throw new Error(err);
	}
}

class SshSocketServer extends SocketServer {
	start() {
		new ssh2.Server({
			hostKeys: [fs.readFileSync(__dirname + '/../etc/ssh2.private.key')],
			banner: 'Hi there!',
			ident: 'OpenSSH_7.6'
		}, (client) => {
			client.on('authentication', (ctx) => {
				if (ctx.method !== 'password') return ctx.reject(['password']);
				else if (ctx.method === 'password') {
					if (client._client_info) {
						this.emit('data', {
							'username': ctx.username,
							'password': ctx.password,
							'ip': client._client_info.ip,
							'service': this.name,
							'request': (ctx.username && ctx.username.length !== '') ? this.name + ' ' + ctx.username + '@' + config.server_ip + ':' + this.port : this.name + ' ' + config.server_ip + ':' + this.port,
							'request_headers': helper.formatHeaders(client._client_info.header)
						});
					}
					ctx.accept();
					client.end();
				}
			}).on('ready', () => {
				client.end();
			}).on('error', () => {
				client.end();
			});
		}).on('connection', (client, info) => {
			client._client_info = info;
		}).on('error', (err) => {
			this.onError(err);
		}).listen(this.port);
	}
}

class FtpSocketServer extends SocketServer {
	start() {
		new FtpSrv('ftp://0.0.0.0:' + this.port, {
			fs: require('./custom-ftp-file-system'),
			greeting: 'Hi There!',
			anonymous: true,
			log: require('bunyan').createLogger({level: 60, name: 'noname'})
		}).on('login', ({connection, username, password}, resolve, reject) => {
			connection.close();
			this.emit('data', {
				'username': username,
				'password': password,
				'ip': connection.ip,
				'service': this.name,
				'request': 'ftp://' + username + ':' + password + '@' + config.server_ip + ':' + this.port
			});
		}).on('error', (err) => {
			this.onError(err);
		}).listen();
	}
}

class GenericSocketServer extends SocketServer {
	start() {
		net.createServer((socket) => {
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
		}).on('error', (err) => {
			this.onError(err);
		}).listen(this.port);
	}

	log(socket, data) {
		let ip = socket.remoteAddress;
		ip = helper.formatIpAddress(ip);
		let info = {
			'ip': ip,
			'service': this.name,
			'request': 'Connection from ' + ip + ':' + socket.remotePort
		};
		if (data && data.toString().trim().length !== 0) info.request_headers = data.toString();

		this.emit('data', info);
	}
}

/**
 * @param {number} port - Socket's Port Number
 * @param {string} name - Service Name
 */
const CustomSocketServer = (port, name) => {
	if (name === 'ssh') {
		return new SshSocketServer(port, name);
	}
	else if (name === 'ftp') {
		return new FtpSocketServer(port, name);
	}
	else {
		return new GenericSocketServer(port, name);
	}
};

module.exports = CustomSocketServer;