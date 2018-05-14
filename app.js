"use strict";

const config = require('./config');
const express = require('express');
const app = express();
const helmet = require('helmet');
const path = require('path');
const server = require('http').createServer(app);
const io = require('socket.io')(server);
const ssh2 = require('ssh2');
const fs = require('fs');
const escape = require('escape-html');
const mysql_pool = require('mysql').createPool(config.mysql_connection_string);
const spawn = require('child_process').spawn;
const {FtpSrv, FileSystem} = require('ftp-srv');
const net = require('net');

const data = [];
let total_requests_number = 0;

/* Initial MySQL query */
mysql_pool.getConnection(function(err, connection) {
	connection.query('SELECT COUNT(*) as cnt FROM request', function (error, results, fields) {
		total_requests_number = results[0].cnt;
		connection.release();
		if (error) throw error;
	});
});

/* Get recent username/passwords */
let recent_ssh_credentials = () => {
	return new Promise(function(resolve, reject) {
		mysql_pool.getConnection(function(err, connection) {
			let query = `
			SELECT
				username, password
			FROM
				request
			WHERE
				username != ''
			ORDER BY id DESC
			LIMIT 0 , 6
			`;
			connection.query(query, function (error, results, fields) {
				let rows = [];
				connection.release();
				if (error) throw error;
				results.forEach(function(row){
					rows.push({'username': row['username'], 'password': row['password']});
				});
				resolve(rows);
			});
		});
	});
};

/* Websocket server */
io.on('connection', function(socket) {
	recent_ssh_credentials().then(function(rows){
		socket.emit('init', {'data': data, 'total_requests_number': total_requests_number, 'recent_credentials': rows});
	})
});
server.listen(3000);

/* Custom Servers / telnet */
class MyServer {
	constructor(port, name) {
		this.port = port;
		this.name = name;
		this.start();
	}
	start () {
		let server = net.createServer((socket) => {
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
		if (data && data.toString().trim().length !== 0) {
			populateData({
				'ip': ip,
				'service': this.name,
				'request': 'Connection from ' + ip + ':' + socket.remotePort,
				'request_headers': data.toString()
			});
		}
		else {
			populateData({
				'ip': ip,
				'service': this.name,
				'request': 'Connection from ' + ip + ':' + socket.remotePort
			});
		}
	}
}
let telnet = new MyServer(23, 'telnet');
let dns = new MyServer(53, 'DNS');
let pop = new MyServer(110, 'POP3');
let netbios1 = new MyServer(137, 'NetBIOS');
let netbios2 = new MyServer(138, 'NetBIOS');
let netbios3 = new MyServer(139, 'NetBIOS');
let mysql_server = new MyServer(3306, 'MySQL');
let mssql = new MyServer(1433, 'MSSQL');
let mongodb = new MyServer(27017, 'MongoDB');
let memcached = new MyServer(11211, 'memcached');

/* Ping (tcpdump) */
let cmd = 'tcpdump';
let args = ['-nvvv', '-l', '-i', 'eth0', 'icmp', 'and', 'icmp[icmptype]=icmp-echo'];
const child = spawn(cmd, args, {stdio: ['ignore', 'pipe', 'ignore']});
child.stdout.on('data', function (data) {
	try {
		let echo_request = data.toString();
		let echo_request_ip = echo_request.split("\n")[1].split(">")[0].trim();
		populateData({
			'ip': echo_request_ip,
			'service': 'ping',
			'request': 'ICMP echo request from ' + echo_request_ip,
			'request_headers': echo_request
		});
	}
	catch (error) {}
});

/* FTP Server */
class MyFileSystem extends FileSystem {
	constructor() {super(...arguments);}
	currentDirectory() {return;}
	get(fileName) {return;}
	list(path = '.') {return;}
	chdir(path = '.') {return;}
	write(fileName, {append = false, start = undefined} = {}) {return;}
	read(fileName, {start = undefined} = {}) {return;}
	delete(path) {return;}
	mkdir(path) {return;}
	rename(from, to) {return;}
	chmod(path, mode) {return;}
}
const ftpServer = new FtpSrv('ftp://0.0.0.0:21', {fs: MyFileSystem, greeting: 'Hi There!', anonymous: true, log: require('bunyan').createLogger({level:60, name: 'noname'})});
ftpServer.on('login', ({connection, username, password}, resolve, reject) => {
	connection.close();

	populateData({
		'username': username,
		'password': password,
		'ip': connection.ip,
		'service': 'ftp',
		'request': 'ftp://' + username + ':' + password + '@' + config.server_ip + ':21'
	});
});
ftpServer.listen();

/* SSH2 Server */
const ssh2_server = new ssh2.Server({hostKeys: [fs.readFileSync('ssh2.private.key')],banner: 'Hi there!',ident: 'OpenSSH_7.6'}, function(client) {
	client.on('authentication', function(ctx) {
		if (ctx.method !== 'password') return ctx.reject(['password']);
		if (ctx.method === 'password') {
			if (client._client_info) {
				populateData({
					'username': ctx.username,
					'password': ctx.password,
					'ip': client._client_info.ip,
					'service': 'ssh',
					'request': (ctx.username && ctx.username.length !== '') ? 'ssh ' + ctx.username + '@' + config.server_ip + ':22' : 'ssh ' + config.server_ip + ':22',
					'request_headers': processHeaders(client._client_info.header)
				});
			}
			ctx.accept();
			client.end();
		}
		else {
			// if no signature present, that means the client is just checking
			// the validity of the given public key
			ctx.accept();
		}
	}).on('ready', function() {
		client.end();
	}).on('error', function() {
		client.end();
	});
}).listen(22);
ssh2_server.on('connection', function (client, info) { client._client_info = info; });

/* Express App */
app.enable('trust proxy', 1);
app.use(helmet());
app.use(function (req, res, next) {
	if (req.hostname !== config.hostname || req.protocol === 'http') {
		populateData({
			'ip': req.ip,
			'service': req.protocol,
			'request': req.hostname ? req.method + ' ' + req.protocol + '://' + req.hostname + req.originalUrl : req.method + ' ' + req.originalUrl,
			'http_request_path': req.originalUrl,
			'request_headers': processHeaders(req.headers)
		});
		res.redirect('https://' + config.hostname + req.originalUrl);
	}
	else {
		populateData({
			'ip': req.ip,
			'service': req.protocol,
			'request': req.method + ' ' + req.originalUrl,
			'http_request_path': req.originalUrl,
			'request_headers': processHeaders(req.headers)
		});
		next()
	}
});

app.use(express.static('static'));

app.get('/', function (req, res) {
	res.sendFile(path.join(__dirname + '/view/index.html'));
});
app.all('*', function (req, res) {
	if (req.hostname === config.hostname || req.hostname === config.server_ip) {
		let response = req.hostname ? req.method + ' ' + req.protocol + '://' + req.hostname + req.originalUrl : req.method + ' ' + req.originalUrl;
		res.status(200).send(escape(response));
	}
	else {
		res.sendStatus(404);
	}
});

app.listen(3001);

const populateData = function(item) {
	total_requests_number++;
	item.timestamp = Date.now();

	if (item.ip && item.ip.substr(0, 7) === "::ffff:") item.ip = item.ip.substr(7);

	data[data.length] = item;

	io.emit('broadcast', item);

	let request = {'ip': item.ip, 'service': item.service, 'request': item.request, 'request_headers': item.request_headers};
	if ('username' in item) request.username = item['username'];
	if ('password' in item) request.password = item['password'];
	if ('http_request_path' in item) request.http_request_path = item['http_request_path'];
	mysql_pool.getConnection(function(err, connection) {
		let query = connection.query('INSERT INTO request SET ?', request, function (error, results, fields) {
			connection.release();
			if (error) throw error;
		});
	});
};

const processHeaders = function(headers, indent) {
	if (!headers) return;
	indent = indent ? indent : '';
	let s = '';
	for (let key in headers) {
		let val = headers[key];
		if (typeof val === 'object' && val !== null) {
			s+= key + ':\r\n';
			s+= processHeaders(val, indent + " - ");
		}
		else s+= indent + key + ': ' + val + '\r\n';
	}

	return s;
};

/* Cleaning Up Old Data */
setInterval(function(){
	if (!data.length) return;

	for (let i = data.length - 1; i >= 0; i -= 1) {
		let item = data[i];
		if (Date.now() - item.timestamp > 2000) {
			data.splice(i, 1);
		}
	}
}, 2000);

/* Restart/Kill Signal from supervisor */
process.on('SIGTERM', function () {
	try {
		child.kill();
	}catch (error) {}
	server.close(function () {
		process.exit(0);
	});
});