"use strict";

const app = {
	modal: null,
	requests_total: 0,
	requests_since_launch: 0,
	favico: null,

	init: function() {
		app.modal = new tingle.modal();

		$(document).on('click', '.full-text', function(event) {
			event.preventDefault();
			let fullTextTitle = $(this).parent().data('fullTextTitle');
			let content = '';
			if (fullTextTitle) content+= '<h1>' + fullTextTitle + '</h1>';
			content+= '<pre>';
			content+= $(this).parent().data('fullText');
			content+= '</pre>';
			app.modal.setContent(content);
			app.modal.open();
		});
		app.favico = new Favico({
			animation: 'none'
		});
	},

	renderData: function(data) {
		if (!data) return;

		for (let i in data) {
			app.renderRow(data[i]);
		}
	},

	renderRow: function (data) {
		if (!data || data.request.length === 0) return;

		let current_date = new Date();
		current_date.setTime(data.timestamp);

		let modal_title = (data.service === 'http' || data.service === 'https') ? 'Headers' : false;

		let html = '';
		html+= '<tr>';
		html+= app.renderCell(('0' + current_date.getHours()).slice(-2) + ':' + ('0' + current_date.getMinutes()).slice(-2) + ':' + ('0' + current_date.getSeconds()).slice(-2) + '.' + current_date.getMilliseconds());
		html+= app.renderCell(data.ip);
		html+= app.renderCell(data.service);
		html+= app.renderCell(data.request, modal_title, data.request_headers);
		html+= '</tr>';

		$('#data-table').find('tbody').append( html );

		if (data.username) app.updateCredentials(data);

		app.updateStats();
	},

	renderCell: function(text, fullTextTitle, fullText) {
		let td = '';
		let extra = '';
		let text_to_display = text ? app.escapeHtml(text.substr(0, 60)) : '-';
		let title = text ? app.escapeHtml(text) : '';

		if (fullText && fullText.length !== 0) {
			extra += ' data-full-text=\'' + app.escapeHtml(fullText) + '\' ';
			if (fullTextTitle && fullTextTitle.length !== 0) extra += ' data-full-text-title=\'' + app.escapeHtml(fullTextTitle) + '\' ';
		}
		td+= '<td' + extra + '>';
		if (extra.length !== 0) td+= '<a href="#" class="full-text" title="' + title + '">' + text_to_display + '</a>';
		else td+= '<span title="' + title + '">' + text_to_display + '</span>';
		td+= '</td>';

		return td;
	},

	updateStats: function() {
		app.requests_total++;
		app.requests_since_launch++;
		$('#requests_total').text(app.requests_total);
		$('#requests_since_launch').text(app.requests_since_launch);
		app.favico.badge(app.requests_since_launch);
	},

	renderCredentials: function(data) {
		if (!data || !(0 in data)) return;

		let html = '';
		for (let i in data) {
			html+= '<div>' + app.escapeHtml(data[i]['username']) + ':' + app.escapeHtml(data[i]['password']) + '</div>';
		}
		$('#recent_credential').html(html);
	},

	renderPopularRequests: function(data) {
		if (!data || !(0 in data)) return;

		let html = '';
		for (let i in data) {
			html+= '<div>' + app.escapeHtml(data[i]['http_request_path']) + '</div>';
		}
		$('#http_requests').html(html);
	},

	updateCredentials: function(data) {
		let html = '<div>' + app.escapeHtml(data['username']) + ':' + app.escapeHtml(data['password']) + '</div>';
		$('#recent_credential').prepend(html);
		$('#recent_credential div:last').remove();
	},

	entityMap: {
		'&': '&amp;',
		'<': '&lt;',
		'>': '&gt;',
		'"': '&quot;',
		"'": '&#39;',
		'/': '&#x2F;',
		'`': '&#x60;',
		'=': '&#x3D;'
	},
	escapeHtml: function (string) {
		return String(string).replace(/[&<>"'`=\/]/g, function (s) {
			return app.entityMap[s];
		});
	}
};

let socket = io();

socket.on('init', function(init_data) {
	app.requests_total = init_data['total_requests_number'];
	app.renderData(init_data['data']);
	app.renderCredentials(init_data['recent_credentials']);
	app.renderPopularRequests(init_data['popular_requests']);
});
socket.on('broadcast', function(data) {
	app.renderRow(data);
});

$(document).ready(function(){
	app.init();
});