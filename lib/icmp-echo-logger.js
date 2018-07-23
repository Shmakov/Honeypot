"use strict";

const EventEmitter = require('events');
const { spawn } = require('child_process');

class IcmpEchoLogger extends EventEmitter {
	constructor() {
		super();
		this.start();
	}

	start() {
		let cmd = 'tcpdump';
		let args = ['-nvvv', '-l', '-i', 'eth0', 'icmp', 'and', 'icmp[icmptype]=icmp-echo'];
		this.tcpdumpProcess = spawn(cmd, args, {stdio: ['ignore', 'pipe', 'ignore']});
		this.tcpdumpProcess.stdout.on('data', (data) => {
			try {
				let echo_request = data.toString();
				let echo_request_ip = echo_request.split("\n")[1].split(">")[0].trim();
				this.emit('data', {
					'ip': echo_request_ip,
					'service': 'ping',
					'request': 'ICMP echo request from ' + echo_request_ip,
					'request_headers': echo_request
				});
			}
			catch (error) {
				console.log('IcmpEchoLogger Exception:', error);
			}
		});
	}
}

module.exports = IcmpEchoLogger;