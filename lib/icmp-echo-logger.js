"use strict";

const EventEmitter = require('events');
const {spawn} = require('child_process');
const chalk = require('chalk');

class IcmpEchoLogger extends EventEmitter {
	constructor() {
		super();
		this.start();
	}

	start() {
		let cmd = 'tcpdump';
		let args = ['-nvvv', '-l', '-i', 'eth0', 'icmp', 'and', 'icmp[icmptype]=icmp-echo'];
		this.tcpdumpProcess = spawn(cmd, args, {stdio: ['ignore', 'pipe', 'ignore']});
		this.tcpdumpProcess.on('error', (err) => {
			console.log(chalk.bgYellow.bold('Warning:') + ' Cannot spawn tcpdump. Error code: ' + err.code);
		});
		this.tcpdumpProcess.stdout.on('data', (data) => {
			let echo_request = data.toString();
			let lines = echo_request.split("\n");
			if (lines[1] === undefined) return;
			let ip_address = lines[1].split(">")[0];
			if (ip_address === undefined || ip_address.length === 0) return;
			else ip_address = ip_address.trim();

			this.emit('data', {
				'ip': ip_address,
				'service': 'ping',
				'request': 'ICMP echo request from ' + ip_address,
				'request_headers': echo_request
			});
		});
	}
}

module.exports = IcmpEchoLogger;