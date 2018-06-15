"use strict";

const Stats = {
	data: {},

	init: function(data) {
		this.data = data;

		google.charts.load('current', {'packages':['table']});
		google.charts.setOnLoadCallback(Stats.drawServicesTable);
		window.setTimeout(() =>{
			Stats.drawServices();
		}, 0);
	},

	drawServices: function() {
		let series_data = [];
		let other_threshold = 15;
		let other_series = null;
		for (let i = 0; i < Stats.data.services.length; i++) {
			let row = Stats.data.services[i];
			if (i >= other_threshold) {
				if (other_series === null) other_series = {'name': 'Other', 'y': 0};
				other_series.y+= row['total'];
			}
			else {
				series_data.push({'name': row['service'], 'y': row['total']});
			}
		}
		if (other_series !== null) series_data.push(other_series);
		Highcharts.chart('piechart', {
			credits: false,
			chart: {
				plotBackgroundColor: null,
				plotBorderWidth: null,
				plotShadow: false,
				type: 'pie'
			},
			title: false,
			tooltip: {
				pointFormat: '<b>{point.percentage:.1f}%</b>'
			},
			plotOptions: {
				pie: {
					allowPointSelect: true,
					cursor: 'pointer',
					dataLabels: {
						enabled: true,
						format: '<b>{point.name}</b>: {point.percentage:.1f} %',
						style: {
							color: (Highcharts.theme && Highcharts.theme.contrastTextColor) || 'black'
						}
					}
				}
			},
			series: [{
				name: 'Services',
				colorByPoint: true,
				data: series_data
			}]
		});
	},

	drawServicesTable: function() {
		let data = new google.visualization.DataTable();
		data.addColumn('string', 'Service');
		data.addColumn('number', 'Requests #');
		for (let i = 0; i < Stats.data.services.length; i++) {
			let row = Stats.data.services[i];
			data.addRow([row['service'], row['total']]);
		}

		let table = new google.visualization.Table(document.getElementById('services-table'));

		let options = {
			showRowNumber: true,
			width: '100%',
			height: '100%'
		};
		table.draw(data, options);
	}
};