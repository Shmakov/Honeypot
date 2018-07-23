"use strict";

let config;
try {
	config = require('./config');
} catch (err) {
	console.log("Error: config not found. Please create `./config.js` based on the `./config.js.template`.");
	return;
}

const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const helmet = require('helmet');
const server = require('http').Server(app);
const io = require('socket.io')(server);
const escape = require('escape-html');
const { spawn } = require('child_process');
const CustomSocketServer = require('./lib/custom-socket-server');
const helper = require('./lib/helper');
const tcp_ports = require('./lib/tcp-ports');

const data = [];
let monthly_stats;
let total_requests_number = 0;
let recent_credentials = null;

/* Socket.io WebSocket Server: on connection */
io.on('connection', (socket) => {
	socket.emit('init', {
		'data': data,
		'total_requests_number': total_requests_number,
		'recent_credentials': recent_credentials
	});
});

/**
 * Custom Socket Server: listening on ~128 most common TCP ports
 * @see: ./lib/tcp-ports
 */
for (let port in tcp_ports) {
	(CustomSocketServer(port, tcp_ports[port])).on('data', (data) => {
		emitData(data);
	});
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
if (config.nginx_reverse_proxy) app.enable('trust proxy', 1);
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
	if (req.hostname !== config.hostname || (req.protocol === 'http' && config.https_only)) {
		if (req.hostname) item.request = req.method + ' ' + req.protocol + '://' + req.hostname + req.originalUrl;
		emitData(item);
		res.redirect((config.https_only ? 'https' : 'http') + '://' + config.hostname + req.originalUrl);
	}
	else {
		emitData(item);
		next()
	}
});
app.use(express.static('static'));
app.get('/', (req, res) => {
	res.sendFile('view/index.html' , {root: __dirname, lastModified: false, headers: {'Cache-Control': 'no-cache, no-store, must-revalidate', 'Expires': '0'}});
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
server.listen(config.nginx_reverse_proxy === true ? config.express_js_alternative_port : 80);

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