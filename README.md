# Overview
Low interaction honeypot application that displays real time attacks in the web-interface. Made just for fun and it is not production ready.

Written in Node.js the application listens on 128 most common TCP ports and saves results to the MySQL Database for further analysis. 

## Demo
Web-interface demo available at https://tail-f.shmakov.net/

<p align="center"><img src="etc/images/interface_demo.gif?raw=true"></p>

## How to Deploy
We need nodejs, git and tcpdump
```
sudo yum install git nodejs tcpdump -y
```
Clone the repo, install dependencies and run the app.js. Please make sure that none of your own services are listening on the ports 21, 22, 80 and [~128 more ports](lib/tcp-ports.js).
```
git clone https://github.com/Shmakov/Honeypot.git
cd Honeypot/ && npm install
sudo node app.js # Please think twice before running random person's code with the sudo privileges
```
That is it. You should be able to access the app on the port 80 from your web-browser. 

## Monthly Statistics
Stats for the past 30 days are available at https://tail-f.shmakov.net/stats

Below example is custom-made and displays the data for the month of June 2018:
- There were total of 69 074 requests to the server;
- IP Geolocation based on 11 918 unique IP Addresses;
- IP Geolocation Map is made with the help of Google Maps API and Google Fusion Tables.

<p align="center"><img src="etc/images/stats_demo.png?raw=true"></p>
