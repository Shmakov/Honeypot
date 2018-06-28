"use strict";

const config = require('./config');
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const helmet = require('helmet');
const server = require('http').createServer(app);
const io = require('socket.io')(server);
const ssh2 = require('ssh2');
const fs = require('fs');
const escape = require('escape-html');
const { spawn } = require('child_process');
const FtpSrv = require('ftp-srv');
const CustomSocketServer = require('./lib/custom-socket-server');
const helper = require('./lib/helper');
const tcp_ports = require('./lib/tcp-ports');

const data = [];
let monthly_stats;
let total_requests_number = 0;
let recent_credentials = null;

/* WebSocket Server */
io.on('connection', (socket) => {
	socket.emit('init', {
		'data': data,
		'total_requests_number': total_requests_number,
		'recent_credentials': recent_credentials
	});
});
server.listen(3000);

/**
 * Custom Socket Server: listening on ~128 most common TCP ports
 * @see: ./lib/tcp-ports
 */
for (let port in tcp_ports) {
	(new CustomSocketServer(port, tcp_ports[port])).on('data', (data) => { emitData(data); });
}

/* Catching ICMP echo requests (ping) using tcpdump */
let cmd = 'tcpdump';
let args = ['-nvvv', '-l', '-i', 'eth0', 'icmp', 'and', 'icmp[icmptype]=icmp-echo'];
const tcpdumpProcess = spawn(cmd, args, {stdio: ['ignore', 'pipe', 'ignore']});
tcpdumpProcess.stdout.on('data', (data) => {
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

/* MySQL Helper */
(new helper.Mysql()).on('total_requests_number', (count) => {
	total_requests_number = count;
}).on('recent_credentials', (rows) => {
	// Returns recent SSH/FTP usernames/passwords
	recent_credentials = rows;
}).on('monthly_stats', (stats) => {
	monthly_stats = stats;
});

/* Express App */
app.enable('trust proxy', 1);
app.use(helmet());
app.set('view engine', 'ejs');
app.set('views', './view');
app.use(bodyParser.urlencoded({ extended: true }));
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
app.get('/stats', (req, res) => {
	res.render('stats', {data: monthly_stats})
});
app.all('*', (req, res) => {
	if (req.hostname === config.hostname || req.hostname === config.server_ip) {
		let response = req.hostname ? req.method + ' ' + req.protocol + '://' + req.hostname + req.originalUrl : req.method + ' ' + req.originalUrl;
		if (req.body.length !== 0) response+= "\r\n\r\n" + helper.formatHeaders(req.body);
		res.status(200).send("<pre>" + escape(response) + "</pre>");
	}
	else {
		res.sendStatus(404);
	}
});
app.listen(30101);

/**
 * Emits data to the WebSocket clients and also saves it in the MySQL database
 * @param item
 */
const emitData = (item) => {
	total_requests_number++;

	item.timestamp = Date.now();
	if (item.ip && item.ip.substr(0, 7) === "::ffff:") item.ip = item.ip.substr(7);

	io.emit('broadcast', item);

	data[data.length] = item;

	helper.saveToDatabase(item);
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
		tcpdumpProcess.kill();
	}catch (error) {}

	server.close(() => {
		process.exit(0);
	});
});