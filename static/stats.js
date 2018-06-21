"use strict";

const Stats = {
	data: {},

	init: function(data) {
		this.data = data;

		google.charts.load('current', {'packages':['table']});
		google.charts.setOnLoadCallback(Stats.drawServicesTable);
		google.charts.setOnLoadCallback(Stats.drawCredentialsTable);
		google.charts.setOnLoadCallback(Stats.drawRequestsTable);
		window.setTimeout(() =>{
			Stats.drawServices();
		}, 0);
		window.setTimeout(() =>{
			jQuery('text').css('fill', '#8197b1')
		}, 1000);
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

		Highcharts.theme = {
			colors: ['#023e58', '#2b908f', '#8be586', '#f45b5b', '#7798BF', '#aaeeee', '#ff0066',
				'#eeaaee', '#55BF3B', '#DF5353', '#7798BF', '#aaeeee'],
			chart: {
				backgroundColor: {
					linearGradient: { x1: 0, y1: 0, x2: 1, y2: 1 },
					stops: [
						[0, '#0e1626'],
						[1, '#0e1626']
					]
				},
				style: {
					fontFamily: '\'Unica One\', sans-serif'
				},
				plotBorderColor: '#606063'
			},
			title: {
				style: {
					color: '#E0E0E3',
					textTransform: 'uppercase',
					fontSize: '20px'
				}
			},
			subtitle: {
				style: {
					color: '#E0E0E3',
					textTransform: 'uppercase'
				}
			},
			xAxis: {
				gridLineColor: '#707073',
				labels: {
					style: {
						color: '#E0E0E3'
					}
				},
				lineColor: '#707073',
				minorGridLineColor: '#505053',
				tickColor: '#707073',
				title: {
					style: {
						color: '#A0A0A3'

					}
				}
			},
			yAxis: {
				gridLineColor: '#707073',
				labels: {
					style: {
						color: '#E0E0E3'
					}
				},
				lineColor: '#707073',
				minorGridLineColor: '#505053',
				tickColor: '#707073',
				tickWidth: 1,
				title: {
					style: {
						color: '#A0A0A3'
					}
				}
			},
			tooltip: {
				backgroundColor: 'rgba(0, 0, 0, 0.85)',
				style: {
					color: '#F0F0F0'
				}
			},
			plotOptions: {
				series: {
					dataLabels: {
						color: '#B0B0B3'
						// color: '#8197b1'
					},
					marker: {
						lineColor: '#333'
					}
				},
				boxplot: {
					fillColor: '#505053'
				},
				candlestick: {
					lineColor: 'white'
				},
				errorbar: {
					color: 'white'
				}
			},
			legend: {
				itemStyle: {
					color: '#E0E0E3'
				},
				itemHoverStyle: {
					color: '#FFF'
				},
				itemHiddenStyle: {
					color: '#606063'
				}
			},
			credits: {
				style: {
					color: '#666'
				}
			},
			labels: {
				style: {
					color: '#707073'
				}
			},

			drilldown: {
				activeAxisLabelStyle: {
					color: '#F0F0F3'
				},
				activeDataLabelStyle: {
					color: '#F0F0F3'
				}
			},

			navigation: {
				buttonOptions: {
					symbolStroke: '#DDDDDD',
					theme: {
						fill: '#505053'
					}
				}
			},

			// scroll charts
			rangeSelector: {
				buttonTheme: {
					fill: '#505053',
					stroke: '#000000',
					style: {
						color: '#CCC'
					},
					states: {
						hover: {
							fill: '#707073',
							stroke: '#000000',
							style: {
								color: 'white'
							}
						},
						select: {
							fill: '#000003',
							stroke: '#000000',
							style: {
								color: 'white'
							}
						}
					}
				},
				inputBoxBorderColor: '#505053',
				inputStyle: {
					backgroundColor: '#ffffff',
					color: 'silver'
				},
				labelStyle: {
					color: 'silver'
				}
			},

			navigator: {
				handles: {
					backgroundColor: '#666',
					borderColor: '#AAA'
				},
				outlineColor: '#CCC',
				maskFill: 'rgba(255,255,255,0.1)',
				series: {
					color: '#7798BF',
					lineColor: '#A6C7ED'
				},
				xAxis: {
					gridLineColor: '#505053'
				}
			},

			scrollbar: {
				barBackgroundColor: '#808083',
				barBorderColor: '#808083',
				buttonArrowColor: '#CCC',
				buttonBackgroundColor: '#606063',
				buttonBorderColor: '#606063',
				rifleColor: '#FFF',
				trackBackgroundColor: '#404043',
				trackBorderColor: '#404043'
			},

			// special colors for some of the
			legendBackgroundColor: 'rgba(0, 0, 0, 0.5)',
			background2: '#505053',
			// dataLabelsColor: '#B0B0B3',
			textColor: '#C0C0C0',
			contrastTextColor: '#F0F0F3',
			maskColor: 'rgba(255,255,255,0.3)'
		};
		Highcharts.setOptions(Highcharts.theme);

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
	},

	drawRequestsTable: function() {
		let data = new google.visualization.DataTable();
		data.addColumn('string', 'Request Path');
		data.addColumn('number', '#');
		for (let i = 0; i < Stats.data.requests.length; i++) {
			let row = Stats.data.requests[i];
			let request = row['request'].length > 64 ? row['request'].substring(0, 64) + '...' : row['request'];
			data.addRow([request, row['total']]);
		}

		let table = new google.visualization.Table(document.getElementById('requests-table'));

		let options = {
			showRowNumber: true,
			width: '100%',
			height: '100%'
		};
		table.draw(data, options);
	},

	drawCredentialsTable: function() {
		let data = new google.visualization.DataTable();
		data.addColumn('string', 'Username/Password');
		data.addColumn('number', '#');
		for (let i = 0; i < Stats.data.credentials.length; i++) {
			let row = Stats.data.credentials[i];
			data.addRow([row['credentials'], row['total']]);
		}

		let table = new google.visualization.Table(document.getElementById('credentials-table'));

		let options = {
			showRowNumber: true,
			width: '100%',
			height: '100%'
		};
		table.draw(data, options);
	}
};