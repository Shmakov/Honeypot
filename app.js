"use strict";

const config = require('./config');
const express = require('express');
const app = express();
const helmet = require('helmet');
const server = require('http').createServer(app);
const io = require('socket.io')(server);
const ssh2 = require('ssh2');
const fs = require('fs');
const escape = require('escape-html');
const mysql_pool = require('mysql').createPool(config.mysql_connection_string);
const spawn = require('child_process').spawn;
const FtpSrv = require('ftp-srv');
const CustomSocketServer = require('./lib/custom-socket-server');
const helper = require('./lib/helper');

const data = [];
let total_requests_number = 0;
let recent_credentials = null;
let popular_requests = null;

/* WebSocket server */
io.on('connection', (socket) => {
	socket.emit('init', {
		'data': data,
		'total_requests_number': total_requests_number,
		'recent_credentials': recent_credentials,
		'popular_requests': popular_requests
	});
});
server.listen(3000);

/* Basic Custom Socket servers listening on different ports */
(new CustomSocketServer(23,    'telnet')).on('data', (data) => { emitData(data); });
(new CustomSocketServer(53,    'DNS')).on('data', (data) => { emitData(data); });
(new CustomSocketServer(110,   'POP3')).on('data', (data) => { emitData(data); });
(new CustomSocketServer(137,   'NetBIOS')).on('data', (data) => { emitData(data); });
(new CustomSocketServer(138,   'NetBIOS')).on('data', (data) => { emitData(data); });
(new CustomSocketServer(139,   'NetBIOS')).on('data', (data) => { emitData(data); });
(new CustomSocketServer(3306,  'MySQL')).on('data', (data) => { emitData(data); });
(new CustomSocketServer(1433,  'MSSQL')).on('data', (data) => { emitData(data); });
(new CustomSocketServer(27017, 'MongoDB')).on('data', (data) => { emitData(data); });
(new CustomSocketServer(11211, 'memcached')).on('data', (data) => { emitData(data); });

/* Catching ICMP echo requests (ping) using tcpdump */
let cmd = 'tcpdump';
let args = ['-nvvv', '-l', '-i', 'eth0', 'icmp', 'and', 'icmp[icmptype]=icmp-echo'];
const child = spawn(cmd, args, {stdio: ['ignore', 'pipe', 'ignore']});
child.stdout.on('data', (data) => {
	try {
		let echo_request = data.toString();
		let echo_request_ip = echo_request.split("\n")[1].split(">")[0].trim();
		emitData({
			'ip': echo_request_ip,
			'service': 'ping',
			'request': 'ICMP echo request from ' + echo_request_ip,
			'request_headers': echo_request
		});
	}
	catch (error) {}
});

/* FTP Server */
const ftpServer = new FtpSrv('ftp://0.0.0.0:21', {
	fs: require('./lib/custom-ftp-file-system'),
	greeting: 'Hi There!',
	anonymous: true,
	log: require('bunyan').createLogger({level: 60, name: 'noname'})
}).on('login', ({connection, username, password}, resolve, reject) => {
	connection.close();
	emitData({
		'username': username,
		'password': password,
		'ip': connection.ip,
		'service': 'ftp',
		'request': 'ftp://' + username + ':' + password + '@' + config.server_ip + ':21'
	});
}).listen();

/* SSH2 Server */
const ssh2_server = new ssh2.Server({
	hostKeys: [fs.readFileSync('etc/ssh2.private.key')],
	banner: 'Hi there!',
	ident: 'OpenSSH_7.6'
}, (client) => {
	client.on('authentication', (ctx) => {
		if (ctx.method !== 'password') return ctx.reject(['password']);
		if (ctx.method === 'password') {
			if (client._client_info) {
				emitData({
					'username': ctx.username,
					'password': ctx.password,
					'ip': client._client_info.ip,
					'service': 'ssh',
					'request': (ctx.username && ctx.username.length !== '') ? 'ssh ' + ctx.username + '@' + config.server_ip + ':22' : 'ssh ' + config.server_ip + ':22',
					'request_headers': helper.formatHeaders(client._client_info.header)
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
	}).on('ready', () => {
		client.end();
	}).on('error', () => {
		client.end();
	});
}).on('connection', (client, info) => {
	client._client_info = info;
}).listen(22);

/* MySQL query: total number of requests */
mysql_pool.getConnection((err, connection) => {
	connection.query('SELECT COUNT(*) as cnt FROM request', (error, results, fields) => {
		total_requests_number = results[0].cnt;
		connection.release();
		if (error) throw error;
	});
});

/* Get recent username/passwords and most popular pages and update them periodically */
const getRecentSshCredentials = () => {
	mysql_pool.getConnection((err, connection) => {
		let query = `SELECT username, password FROM request WHERE username != '' ORDER BY id DESC LIMIT 0, 6`;
		connection.query(query, (error, results, fields) => {
			let rows = [];
			connection.release();
			if (error) throw error;
			results.forEach((row) => {
				rows.push({'username': row['username'], 'password': row['password']});
			});
			recent_credentials = rows;
		});
	});
};
const getMostPopularRequests = () => {
	mysql_pool.getConnection((err, connection) => {
		let query = `SELECT http_request_path, COUNT(*) AS cnt FROM request WHERE http_request_path IS NOT NULL GROUP BY http_request_path ORDER BY cnt DESC LIMIT 0, 6`;
		connection.query(query, (error, results, fields) => {
			let rows = [];
			connection.release();
			if (error) throw error;
			results.forEach((row) => {
				rows.push({'http_request_path': row['http_request_path']});
			});
			popular_requests = rows;
		});
	});
};
getRecentSshCredentials();
getMostPopularRequests();
setInterval(getRecentSshCredentials, 60 * 1000); // once a minute
setInterval(getMostPopularRequests, 3600 * 1000); // once an hour

/* Express App */
app.enable('trust proxy', 1);
app.use(helmet());
app.use((req, res, next) => {
	let item = {
		'ip': req.ip,
		'service': req.protocol,
		'request': req.method + ' ' + req.originalUrl,
		'http_request_path': req.originalUrl,
		'request_headers': helper.formatHeaders(req.headers)
	};
	if (req.hostname !== config.hostname || req.protocol === 'http') {
		if (req.hostname) item.request = req.method + ' ' + req.protocol + '://' + req.hostname + req.originalUrl;
		emitData(item);
		res.redirect('https://' + config.hostname + req.originalUrl);
	}
	else {
		emitData(item);
		next()
	}
});
app.use(express.static('static'));
app.get('/', (req, res) => {
	res.sendFile('view/index.html' , { root : __dirname});
});
app.all('*', (req, res) => {
	if (req.hostname === config.hostname || req.hostname === config.server_ip) {
		let response = req.hostname ? req.method + ' ' + req.protocol + '://' + req.hostname + req.originalUrl : req.method + ' ' + req.originalUrl;
		res.status(200).send(escape(response));
	}
	else {
		res.sendStatus(404);
	}
});
app.listen(3001);

/**
 * Emits data to the socket clients and also saves it in the MySQL database
 * @param item
 */
const emitData = (item) => {
	total_requests_number++;
	item.timestamp = Date.now();

	if (item.ip && item.ip.substr(0, 7) === "::ffff:") item.ip = item.ip.substr(7);

	data[data.length] = item;

	io.emit('broadcast', item);

	let request = {'ip': item.ip, 'service': item.service, 'request': item.request, 'request_headers': item.request_headers};
	if ('username' in item) request.username = item['username'];
	if ('password' in item) request.password = item['password'];
	if ('http_request_path' in item) request.http_request_path = item['http_request_path'];
	mysql_pool.getConnection((err, connection) => {
		let query = connection.query('INSERT INTO request SET ?', request, (error, results, fields) => {
			connection.release();
			if (error) throw error;
		});
	});
};

/* Cleaning Up Old Data */
setInterval(() => {
	if (!data.length) return;

	for (let i = data.length - 1; i >= 0; i -= 1) {
		let item = data[i];
		if (Date.now() - item.timestamp > 2000) {
			data.splice(i, 1);
		}
	}
}, 2000);

/* Restart/Kill Signal from supervisor */
process.on('SIGTERM', () => {
	try {
		child.kill();
	}catch (error) {}
	server.close(() => {
		process.exit(0);
	});
});