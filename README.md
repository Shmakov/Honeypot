# Overview
Low interaction honeypot application that displays real time attacks in the web-interface. Made just for fun and it is not production ready.

Written in Node.js the application listens on 128 most common TCP ports and saves results to the MySQL Database for further analysis. 

## Demo
Web-interface demo available at https://tail-f.shmakov.net/

<p align="center"><img src="etc/images/interface_demo.gif?raw=true"></p>

## Monthly Statistics
Stats for the past 30 days are available at https://tail-f.shmakov.net/stats

Below example is custom-made and displays the data for the month of June 2018:
- There were total of 69 074 requests to the server;
- IP Geolocation based on 11 918 unique IP Addresses;
- IP Geolocation Map is made with the help of Google Maps API and Google Fusion Tables.

<p align="center"><img src="etc/images/stats_demo.png?raw=true"></p>
