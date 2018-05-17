"use strict";

const config = require('./../config');
const mysqlPool = require('mysql').createPool(config.mysql_connection_string);
const EventEmitter = require('events');

class Mysql extends EventEmitter {
	constructor() {
		super();

		this.getTotalRequestsNumber();
		this.getRecentSshCredentials();
		this.getMostPopularRequests();
		setInterval(() => { this.getRecentSshCredentials(); }, 60 * 1000); // once a minute
		setInterval(() => { this.getMostPopularRequests(); }, 3600 * 1000); // once an hour
	}

	getTotalRequestsNumber() {
		mysqlPool.getConnection((err, connection) => {
			connection.query('SELECT COUNT(*) as cnt FROM request', (error, results, fields) => {
				connection.release();
				if (error) throw error;

				this.emit('total_requests_number', results[0].cnt);
			});
		});
	}

	getRecentSshCredentials() {
		mysqlPool.getConnection((err, connection) => {
			let query = `SELECT username, password FROM request WHERE username != '' ORDER BY id DESC LIMIT 0, 6`;
			connection.query(query, (error, results, fields) => {
				let rows = [];
				connection.release();
				if (error) throw error;
				results.forEach((row) => {
					rows.push({'username': row['username'], 'password': row['password']});
				});

				this.emit('recent_credentials', rows);
			});
		});
	}

	getMostPopularRequests() {
		mysqlPool.getConnection((err, connection) => {
			let query = `SELECT http_request_path, COUNT(*) AS cnt FROM request WHERE http_request_path IS NOT NULL GROUP BY http_request_path ORDER BY cnt DESC LIMIT 0, 6`;
			connection.query(query, (error, results, fields) => {
				let rows = [];
				connection.release();
				if (error) throw error;
				results.forEach((row) => {
					rows.push({'http_request_path': row['http_request_path']});
				});
				this.emit('popular_requests', rows);
			});
		});
	}
}

const saveToDatabase = (item) => {
	let request = {
		'ip': item.ip,
		'service': item.service,
		'request': item.request,
		'request_headers': item.request_headers
	};
	if ('username' in item) request.username = item['username'];
	if ('password' in item) request.password = item['password'];
	if ('http_request_path' in item) request.http_request_path = item['http_request_path'];

	mysqlPool.getConnection((err, connection) => {
		let query = connection.query('INSERT INTO request SET ?', request, (error, results, fields) => {
			connection.release();
			if (error) throw error;
		});
	});
};

const formatHeaders = (headers, indent) => {
	if (!headers) return;
	indent = indent ? indent : '';
	let s = '';
	for (let key in headers) {
		let val = headers[key];
		if (typeof val === 'object' && val !== null) {
			s+= key + ':\r\n';
			s+= formatHeaders(val, indent + " - ");
		}
		else s+= indent + key + ': ' + val + '\r\n';
	}

	return s;
};

module.exports = {
	formatHeaders: formatHeaders,
	saveToDatabase: saveToDatabase,
	Mysql: Mysql
};