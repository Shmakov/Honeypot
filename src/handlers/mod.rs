//! Protocol handlers module

pub mod tcp;
pub mod ssh;
pub mod ftp;
pub mod telnet;
pub mod icmp;

use anyhow::Result;
use std::sync::Arc;
use tracing::info;

use crate::config::Config;
use crate::db::{Database, WriteSender};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

/// TCP ports to listen on (excludes 80/443 used by web server)
/// 1024+ ports based on nmap's top scanned ports and common attack targets
pub const TCP_PORTS: &[(u16, &str)] = &[
    // === WELL-KNOWN PORTS (1-1023) ===
    // Core services
    (1, "tcpmux"), (7, "echo"), (9, "discard"), (11, "systat"), (13, "daytime"),
    (15, "netstat"), (17, "qotd"), (19, "chargen"), (20, "ftp-data"), (21, "ftp"),
    (22, "ssh"), (2222, "ssh-alt"), (23, "telnet"), (25, "smtp"), (26, "rsftp"), (37, "time"),
    (42, "nameserver"), (43, "whois"), (49, "tacacs"), (53, "dns"),
    // Mail & messaging
    (57, "priv-term"), (66, "sqlnet"), (67, "dhcps"), (68, "dhcpc"), (69, "tftp"),
    (70, "gopher"), (79, "finger"), (81, "http-alt"), (82, "xfer"), (83, "mit-ml-dev"),
    (84, "ctf"), (85, "mit-ml-dev2"), (87, "priv-term-l"), (88, "kerberos"),
    (89, "su-mit-tg"), (90, "dnsix"), (98, "linuxconf"), (99, "metagram"),
    (100, "newacct"), (101, "hostname"), (102, "iso-tsap"), (104, "acr-nema"),
    (106, "pop3pw"), (109, "pop2"), (110, "pop3"), (111, "rpcbind"), (113, "ident"),
    (115, "sftp"), (117, "uucp-path"), (118, "sqlserv"), (119, "nntp"), (123, "ntp"),
    (129, "pwdgen"), (135, "msrpc"), (137, "netbios-ns"), (138, "netbios-dgm"),
    (139, "netbios-ssn"), (143, "imap"), (144, "news"), (146, "iso-tp0"),
    (161, "snmp"), (162, "snmptrap"), (163, "cmip-man"), (177, "xdmcp"),
    (179, "bgp"), (194, "irc"), (199, "smux"),
    // Authentication & directory
    (213, "ipx"), (218, "mpp"), (220, "imap3"), (259, "esro-gen"), (264, "bgmp"),
    (280, "http-mgmt"), (300, "thinlinc"), (311, "asip-webadmin"), (318, "pkix-timestamp"),
    (366, "odmr"), (369, "rpc2portmap"), (371, "clearcase"), (383, "hp-alarm-mgr"),
    (384, "arns"), (387, "aurp"), (389, "ldap"), (390, "uis"), (406, "imsp"),
    (407, "timbuktu"), (417, "onmux"), (425, "icad-el"), (427, "svrloc"),
    // (443, "https-skip"), // Skipped - handled by web server, but keep for reference
    (444, "snpp"), (445, "smb"), (458, "appleqtc"), (464, "kpasswd"),
    (465, "smtps"), (475, "cybercash"), (481, "ph"), (497, "retrospect"),
    (500, "isakmp"), (502, "modbus"), (512, "exec"), (513, "login"), (514, "shell"),
    (515, "printer"), (517, "talk"), (518, "ntalk"), (520, "efs"), (524, "ncp"),
    (530, "courier"), (531, "chat"), (532, "netnews"), (533, "netwall"),
    (540, "uucp"), (543, "klogin"), (544, "kshell"), (545, "ekshell"),
    (548, "afp"), (554, "rtsp"), (555, "dsf"), (556, "remotefs"),
    (563, "nntps"), (564, "9pfs"), (587, "submission"), (591, "filemaker"),
    (593, "http-rpc-epmap"), (601, "syslog-conn"), (604, "tunnel"), (631, "ipp"),
    (636, "ldaps"), (639, "msdp"), (646, "ldp"), (648, "rrp"), (651, "ieee-mms"),
    (653, "repscmd"), (654, "aodv"), (655, "tinc"), (657, "rmc"), (660, "mac-srvr-admin"),
    (666, "doom"), (674, "acap"), (688, "realm-rusd"), (690, "vatp"),
    (691, "msexch-routing"), (694, "ha-cluster"), (695, "ieee-mms-ssl"),
    (698, "olsr"), (699, "accessnetwork"), (700, "epp"), (701, "lmp"),
    (702, "iris-beep"), (706, "silc"), (711, "tdp"), (712, "tbrpf"),
    (720, "smqp"), (749, "kerberos-adm"), (750, "kerberos-iv"), (751, "kerberos_master"),
    (752, "qrh"), (753, "rrh"), (754, "tell"), (760, "ns"), (765, "webster"),
    (767, "phonebook"), (769, "vid"), (770, "cadlock2"), (771, "rtip"),
    (772, "cycleserv2"), (773, "submit"), (774, "rpasswd"), (775, "entomb"),
    (776, "wpages"), (777, "multiling-http"), (778, "opsmgr"),
    (779, "decadebrcm"), (780, "wpgs"), (782, "hp-managed-node"),
    (783, "spamassassin"), (787, "qsc"), (800, "mdbs_daemon"), (801, "device"),
    (808, "ccproxy-http"), (843, "flash-policy"), (873, "rsync"), (880, "unknown"),
    (888, "accessbuilder"), (898, "sun-manageconsole"), (900, "omginitialrefs"),
    (901, "smpnameres"), (902, "vmware-auth"), (903, "iss-console-mgr"),
    (911, "xact-backup"), (912, "apex-mesh"), (953, "rndc"), (981, "unknown"),
    (987, "maitrd"), (990, "ftps"), (991, "nas"), (992, "telnets"), (993, "imaps"),
    (994, "ircs"), (995, "pop3s"), (996, "xtreelic"), (997, "maitrd2"),
    (998, "puparp"), (999, "garcon"), (1000, "cadlock"), (1001, "webpush"),
    (1002, "windows-icfw"), (1007, "unknown"), (1009, "unknown"), (1010, "surf"),
    (1011, "unknown"), (1021, "exp1"), (1022, "exp2"), (1023, "netvenuechat"),
    // === REGISTERED PORTS (1024-49151) ===
    // Early registered
    (1024, "kdm"), (1025, "nfs-or-iis"), (1026, "lsa"), (1027, "iis"), (1028, "unknown"),
    (1029, "ms-lsa"), (1030, "iad1"), (1031, "iad2"), (1032, "iad3"),
    (1033, "netinfo-local"), (1034, "activesync"), (1035, "mxxrlogin"),
    (1036, "nsstp"), (1037, "ams"), (1038, "mtqp"), (1039, "sbl"),
    (1040, "netopia-vo1"), (1041, "danf-ak2"), (1042, "afrog"), (1043, "boinc-client"),
    (1044, "dcutility"), (1045, "fpitp"), (1046, "wfremotertm"), (1047, "neod1"),
    (1048, "neod2"), (1049, "td-postman"), (1050, "cma"), (1051, "optima-vnet"),
    (1052, "ddt"), (1053, "remote-as"), (1054, "brvread"), (1055, "ansyslmd"),
    (1056, "vfo"), (1057, "startron"), (1058, "nim"), (1059, "nimreg"),
    (1060, "polestar"), (1061, "kiosk"), (1062, "veracity"), (1063, "kyoceranetdev"),
    (1064, "jstel"), (1065, "syscomlan"), (1066, "fpo-fns"), (1067, "instl_boots"),
    (1068, "instl_bootc"), (1069, "cognex-insight"), (1070, "gmrupdateserv"),
    (1071, "bsquare-voip"), (1072, "cardax"), (1073, "bridgecontrol"),
    (1074, "warmspotMgmt"), (1075, "rdrmshc"), (1076, "dab-sti-c"),
    (1077, "imgames"), (1078, "avocent-proxy"), (1079, "asprovatalk"),
    (1080, "socks"), (1081, "pvuniwien"), (1082, "amt-esd-prot"),
    (1083, "ansoft-lm-1"), (1084, "ansoft-lm-2"), (1085, "webobjects"),
    (1086, "cplscrambler-lg"), (1087, "cplscrambler-in"), (1088, "cplscrambler-al"),
    (1089, "ff-annunc"), (1090, "ff-fms"), (1091, "ff-sm"), (1092, "obrpd"),
    (1093, "proofd"), (1094, "rootd"), (1095, "nicelink"), (1096, "cnrprotocol"),
    (1097, "sunclustermgr"), (1098, "rmiactivation"), (1099, "rmiregistry"),
    (1100, "mctp"), (1102, "adobeserver-1"), (1104, "xrl"), (1105, "ftranhc"),
    (1106, "isoipsigport-1"), (1107, "isoipsigport-2"), (1108, "ratio-adp"),
    (1110, "nfsd-status"), (1111, "lmsocialserver"), (1112, "icp"), (1113, "ltp-deepspace"),
    // Database ports
    (1433, "mssql"), (1434, "mssql-m"), (1521, "oracle"), (1522, "oracle-alt"),
    (1525, "oracle-srv"), (1526, "oracle-lsnr"), (1527, "tlisrv"), (1529, "coauthor"),
    (1530, "rap-service"), (1533, "virtual-places"),
    // Networking & VPN
    (1645, "radius"), (1646, "radacct"), (1688, "nsjtp-ctrl"), (1701, "l2tp"),
    (1718, "h323gatedisc"), (1719, "h323gatestat"), (1720, "h323"), (1723, "pptp"),
    (1755, "wms"), (1761, "cft-0"), (1782, "hp-hcip"), (1783, "fjris"),
    (1801, "msmq"), (1812, "radius-auth"), (1813, "radius-acct"),
    (1863, "msnp"), (1883, "mqtt"), (1900, "upnp"), (1935, "rtmp"),
    // Management & remote access
    (1947, "sentinelsrm"), (1967, "sns-quote"), (1972, "intersys-cache"),
    (1981, "p2pq"), (1984, "bigbrother"), (1986, "licensedaemon"), (1987, "tr-rsrb-p1"),
    (1988, "tr-rsrb-p2"), (1989, "tr-rsrb-p3"), (1990, "stun-p1"), (1991, "stun-p2"),
    (1992, "stun-p3"), (1993, "snmp-tcp-port"), (1994, "stun-port"),
    (1997, "gdp-port"), (1998, "x25-svc-port"), (1999, "tcp-id-port"),
    (2000, "cisco-sccp"), (2001, "dc"), (2002, "globe"), (2003, "finger2"),
    (2004, "mailbox"), (2005, "berknet"), (2006, "invokator"), (2007, "dectalk"),
    (2008, "conf"), (2009, "news"), (2010, "search"), (2013, "raid-am"),
    (2020, "xinupageserver"), (2021, "servexec"), (2022, "down"),
    (2030, "device2"), (2033, "glogger"), (2034, "scoremgr"),
    (2040, "lam"), (2041, "interbase"), (2042, "isis"), (2043, "isis-bcast"),
    (2045, "cdfunc"), (2046, "sdfunc"), (2047, "dls"), (2048, "dls-monitor"),
    (2049, "nfs"), (2065, "dlsrpn"), (2068, "advocentkvm"),
    (2100, "amiganetfs"), (2103, "zephyr-clt"), (2105, "eklogin"), (2106, "ekshell2"),
    (2107, "msmq-mgmt"), (2111, "dsatp"), (2119, "gsigatekeeper"), (2121, "ccproxy-ftp"),
    (2126, "pktcable-cops"), (2135, "gris"), (2144, "lv-ffx"),
    (2160, "apc-2160"), (2161, "apc-2161"), (2170, "eyetv"),
    (2181, "zookeeper"), (2182, "cgn-stat"), (2190, "tivoconnect"),
    (2191, "tvbus"), (2196, "unknown"), (2200, "ici"),
    (2223, "rockwell-csp2"), (2232, "ivs-video"), (2241, "ivsd"),
    (2260, "apc-2260"), (2288, "netml"), (2301, "cpq-wbem"),
    (2323, "3d-nfsd"), (2366, "qip-login"), (2375, "docker"),
    (2376, "docker-tls"), (2379, "etcd-client"), (2380, "etcd-server"),
    (2381, "compaq-https"), (2382, "ms-olap3"), (2383, "ms-olap4"),
    (2393, "ms-olap1"), (2394, "ms-olap2"), (2399, "fmpro-fdal"),
    (2401, "cvspserver"), (2492, "groove"), (2500, "rtsserv"),
    (2522, "windb"), (2525, "ms-v-worlds"), (2557, "nicetec-mgmt"),
    (2598, "citriximaclient"), (2601, "zebra"), (2602, "ripd"),
    (2604, "ospfd"), (2605, "bgpd"), (2607, "connection"), (2608, "wag-service"),
    (2638, "sybase"), (2701, "sms-rcinfo"), (2702, "sms-xfer"),
    (2710, "sso-service"), (2717, "pn-requester"), (2718, "pn-requester2"),
    (2725, "msolap-ptp2"), (2800, "acc-raid"), (2809, "corbaloc"),
    (2811, "gsiftp"), (2869, "icslap"), (2875, "dxmessagebase2"),
    (2909, "funk-dialout"), (2910, "tdaccess"), (2920, "roboeda"),
    (2947, "gpsd"), (2967, "symantec-av"), (2998, "iss-realsec"),
    // Development & web alternatives
    (3000, "ppp"), (3001, "nessus"), (3003, "cgms"), (3005, "deslogin"),
    (3006, "deslogind"), (3007, "lotusmtap"), (3011, "trusted-web"),
    (3013, "gilatskysurfer"), (3017, "event_listener"), (3030, "arepa-cas"),
    (3031, "eppc"), (3050, "gds_db"), (3052, "powerchute"), (3057, "goahead-fldup"),
    (3071, "xplat-replicate"), (3077, "orbix-loc-ssl"), (3128, "squid-http"),
    (3168, "poweronnud"), (3200, "tick-port"), (3211, "avsecuremgmt"),
    (3221, "xnm-clear-text"), (3260, "iscsi-target"), (3261, "winshadow"),
    (3268, "globalcatLDAP"), (3269, "globalcatLDAPssl"), (3283, "netassistant"),
    (3299, "saprouter"), (3300, "ceph"), (3301, "unknown"), (3306, "mysql"),
    (3307, "mysql-alt"), (3310, "dyna-access"), (3311, "mcns-tel-ret"),
    (3312, "appman-server"), (3322, "active-net"), (3323, "active-net2"),
    (3324, "active-net3"), (3325, "active-net4"), (3333, "dec-notes"),
    (3351, "btrieve"), (3367, "satvid-datalnk"), (3369, "satvid-datalnk2"),
    (3370, "satvid-datalnk3"), (3371, "satvid-datalnk4"), (3372, "msdtc"),
    (3389, "rdp"), (3390, "dsc"), (3404, "unknown"), (3476, "nppmp"),
    (3493, "nut"), (3517, "802-11-iapp"), (3527, "beserver-msg-q"),
    (3546, "unknown"), (3551, "apcupsd"), (3580, "nati-svrloc"),
    (3659, "apple-sasl"), (3689, "daap"), (3690, "svn"), (3702, "ws-discovery"),
    (3703, "adobeserver"), (3737, "xpanel"), (3749, "cimtrak"),
    (3766, "sitewatch-s"), (3784, "bfd-control"), (3800, "pwgpsi"),
    (3801, "ibm-mgr"), (3814, "neto-dcs"), (3826, "wormux"),
    (3827, "netmpi"), (3828, "neteh"), (3851, "spectraport"),
    (3869, "ovsam-mgmt"), (3871, "avocent-adsap"), (3878, "fotogcad"),
    (3880, "igrs"), (3889, "dandv-tester"), (3905, "mupdate"),
    (3914, "listcrt-port-2"), (3918, "pktcablemmcops"), (3920, "exasoftport1"),
    (3945, "emcads"), (3971, "lanrevserver"), (3978, "secure-cfg-svr"),
    (3979, "smwan"), (3986, "mapper-ws"), (3995, "iss-mgmt-ssl"),
    (3998, "dnx"), (3999, "remoteanything"), (4000, "remoteanything2"),
    (4001, "newoak"), (4002, "mlchat-proxy"), (4003, "pxc-splr-ft"),
    (4004, "pxc-roid"), (4005, "pxc-pin"), (4006, "pxc-spvr"),
    (4022, "dnox"), (4040, "yo-main"), (4045, "lockd"),
    (4050, "cisco-wafs"), (4064, "ice-srouter"), (4089, "opencore"),
    (4111, "xgrid"), (4125, "rww"), (4126, "ddrepl"),
    (4129, "nuauth"), (4224, "xtell"), (4242, "vrml-multi-use"),
    (4343, "unicall"), (4369, "epmd"), (4443, "pharos"),
    (4444, "krb524"), (4445, "upnotifyp"), (4446, "n1-fwp"),
    (4449, "privatewire"), (4500, "ipsec-nat-t"), (4550, "gds-adppiw-db"),
    (4555, "rsip"), (4567, "tram"), (4662, "edonkey"),
    (4664, "unknown"), (4672, "rfa"), (4711, "trinity-dist"),
    (4730, "gearman"), (4739, "ipfix"), (4750, "ssad"),
    (4786, "smart-install"), (4840, "opcua"), (4843, "opcua-tls"),
    (4848, "glassfish-admin"), (4899, "radmin"), (4900, "hfcs"),
    (4911, "unknown"), (4949, "munin"), (4998, "maybe-veritas"),
    // VNC, X11, and desktop sharing
    (5000, "upnp"), (5001, "commplex"), (5002, "rfe"), (5003, "filemaker"),
    (5004, "avt-profile-1"), (5005, "avt-profile-2"), (5006, "wsm-server"),
    (5007, "wsm-server-ssl"), (5008, "synapsis-edge"), (5009, "airport-admin"),
    (5010, "telelpathstart"), (5011, "telelpathattack"), (5022, "mice"),
    (5025, "scpi-raw"), (5050, "mmcc"), (5051, "ida-agent"),
    (5060, "sip"), (5061, "sip-tls"), (5080, "onscreen"),
    (5084, "llrp"), (5085, "encrypted-llrp"), (5093, "sentinel-lm"),
    (5100, "admd"), (5101, "admdog"), (5102, "admeng"),
    (5120, "unknown"), (5150, "atmp"), (5190, "aol"),
    (5191, "aol-1"), (5192, "aol-2"), (5193, "aol-3"),
    (5200, "targus-getdata"), (5214, "unknown"), (5221, "3exmp"),
    (5222, "xmpp"), (5225, "hp-server"), (5226, "hp-status"),
    (5269, "xmpp-server"), (5280, "xmpp-bosh"), (5298, "presence"),
    (5353, "mdns"), (5357, "wsdapi"), (5400, "pcduo-old"),
    (5405, "pcduo"), (5432, "postgresql"), (5433, "postgresql-alt"),
    (5500, "hotline"), (5510, "secureidprop"), (5544, "unknown"),
    (5550, "sdadmind"), (5555, "freeciv"), (5560, "isqlplus"),
    (5566, "westec-connect"), (5601, "kibana"), (5631, "pcanywheredata"),
    (5632, "pcanywherestat"), (5666, "nrpe"), (5672, "amqp"),
    (5678, "rrac"), (5683, "coap"), (5800, "vnc-http"),
    (5801, "vnc-http-1"), (5802, "vnc-http-2"), (5803, "vnc-http-3"),
    (5850, "unknown"), (5900, "vnc"), (5901, "vnc-1"),
    (5902, "vnc-2"), (5903, "vnc-3"), (5904, "unknown"),
    (5906, "unknown"), (5907, "unknown"), (5910, "cm"),
    (5911, "cpdlc"), (5915, "unknown"), (5922, "unknown"),
    (5938, "teamviewer"), (5950, "unknown"), (5960, "unknown"),
    (5984, "couchdb"), (5985, "winrm"), (5986, "winrm-ssl"),
    (5987, "wbem-rmi"), (5988, "wbem-http"), (5989, "wbem-https"),
    (5998, "ncd-diag"), (5999, "ncd-conf"), (6000, "x11"),
    (6001, "x11-1"), (6002, "x11-2"), (6003, "x11-3"),
    (6004, "x11-4"), (6005, "x11-5"), (6006, "x11-6"),
    (6007, "x11-7"), (6009, "x11-9"), (6025, "x11-25"),
    // Messaging and databases
    (6059, "unknown"), (6100, "synchronet-db"), (6101, "backupexec"),
    (6106, "isdninfo"), (6112, "dtspc"), (6123, "backup-express"),
    (6129, "damewaremr"), (6156, "unknown"), (6346, "gnutella"),
    (6347, "gnutella2"), (6379, "redis"), (6389, "clariion-evr01"),
    (6502, "netop-rc"), (6503, "boks_servc"), (6504, "boks_servm"),
    (6542, "unknown"), (6543, "mythtv"), (6565, "unknown"),
    (6566, "sane-port"), (6567, "unknown"), (6580, "parsec-master"),
    (6600, "mshvlm"), (6646, "unknown"), (6660, "unknown"),
    (6661, "unknown"), (6662, "radmind"), (6663, "unknown"),
    (6664, "unknown"), (6665, "irc-1"), (6666, "irc-2"),
    (6667, "irc"), (6668, "irc-4"), (6669, "irc-5"),
    (6689, "tsa"), (6692, "unknown"), (6699, "napster"),
    (6779, "unknown"), (6788, "smc-http"), (6789, "smc-https"),
    (6792, "unknown"), (6839, "unknown"), (6881, "bittorrent"),
    (6901, "jetstream"), (6969, "acmsoda"),
    // Web and application servers
    (7000, "afs3-fileserver"), (7001, "weblogic"), (7002, "weblogic-ssl"),
    (7004, "afs3-kaserver"), (7007, "afs3-bos"), (7019, "unknown"),
    (7025, "vmsvc-2"), (7070, "realserver"), (7100, "font-service"),
    (7103, "unknown"), (7106, "unknown"), (7200, "fodms"),
    (7201, "dlip"), (7402, "unknown"), (7435, "unknown"),
    (7443, "oracleas-https"), (7474, "neo4j"), (7496, "unknown"),
    (7512, "unknown"), (7625, "unknown"), (7627, "soap-http"),
    (7676, "imqbrokerd"), (7680, "pando-pub"), (7687, "bolt"),
    (7741, "unknown"), (7777, "cbt"), (7778, "interwise"),
    (7779, "vstat"), (7800, "asr"), (7911, "unknown"),
    (7920, "unknown"), (7921, "unknown"), (7937, "nsrexecd"),
    (7938, "lgtomapper"), (7999, "irdmi2"), (8000, "http-alt"),
    (8001, "vcom-tunnel"), (8002, "teradataordbms"), (8007, "ajp12"),
    (8008, "http"), (8009, "ajp13"), (8010, "xmpp"),
    (8011, "unknown"), (8021, "ftp-proxy"), (8022, "oa-system"),
    (8031, "unknown"), (8042, "fs-agent"), (8045, "unknown"),
    // HTTP alternatives and proxies
    (8080, "http-proxy"), (8081, "blackice-icecap"), (8082, "us-cli"),
    (8083, "us-srv"), (8084, "websnp"), (8085, "unknown"),
    (8086, "influxdb"), (8087, "simplifymedia"), (8088, "radan-http"),
    (8089, "splunk"), (8090, "unknown"), (8091, "couchbase-admin"),
    (8093, "unknown"), (8099, "unknown"), (8100, "xprint-server"),
    (8180, "unknown"), (8181, "intermapper"), (8192, "sophos-admin"),
    (8193, "sophos-rep"), (8194, "sophos-update"), (8200, "trivnet1"),
    (8222, "unknown"), (8254, "unknown"), (8290, "unknown"),
    (8291, "mikrotik-api"), (8292, "blp3"), (8300, "tmi"),
    (8333, "bitcoin"), (8383, "m2mservices"), (8400, "cvd"),
    (8402, "abarsd"), (8443, "https-alt"), (8500, "fmtp"),
    (8600, "unknown"), (8649, "ganglia-gmond"), (8651, "unknown"),
    (8652, "unknown"), (8654, "unknown"), (8686, "unknown"),
    (8701, "unknown"), (8800, "sunwebadmin"), (8834, "nessus-api"),
    (8873, "unknown"), (8880, "cddbp-alt"), (8881, "galaxy4d"),
    (8888, "sun-answerbook"), (8899, "ospf-lite"), (8983, "solr"),
    (8994, "unknown"), (9000, "cslistener"), (9001, "tor-orport"),
    (9002, "dynamid"), (9003, "unknown"), (9009, "pichat"),
    (9010, "sdr"), (9011, "unknown"), (9040, "tor-trans"),
    (9042, "cassandra"), (9043, "websm"), (9050, "tor-socks"),
    (9051, "tor-control"), (9060, "unknown"), (9080, "glrpc"),
    (9081, "unknown"), (9084, "unknown"), (9090, "zeus-admin"),
    (9091, "xmltec-xmlmail"), (9092, "kafka"), (9093, "copycat"),
    (9094, "unknown"), (9095, "unknown"), (9099, "unknown"),
    (9100, "jetdirect"), (9101, "jetdirect2"), (9102, "jetdirect3"),
    (9103, "bacula-sd"), (9110, "unknown"), (9111, "DragonIDSConsole"),
    (9160, "apani1"), (9191, "sun-as-jpda"), (9200, "elasticsearch"),
    (9300, "vrace"), (9306, "sphinxql"), (9418, "git"),
    (9443, "tungsten-https"), (9500, "ismserver"), (9535, "mngsuite"),
    (9595, "pds"), (9600, "omhttpmgmt"), (9618, "condor"),
    (9666, "unknown"), (9876, "sd"), (9877, "unknown"),
    (9878, "unknown"), (9898, "monkeycom"), (9900, "unknown"),
    (9917, "unknown"), (9929, "nping-echo"), (9943, "unknown"),
    (9944, "unknown"), (9968, "unknown"), (9998, "unknown"),
    (9999, "abyss"),
    // High ports (10000+)
    (10000, "webmin"), (10001, "scp-config"), (10002, "documentum"),
    (10003, "documentum-s"), (10004, "emcrmirccd"), (10009, "swdtp"),
    (10010, "rxapi"), (10012, "unknown"), (10024, "unknown"),
    (10025, "unknown"), (10082, "unknown"), (10180, "unknown"),
    (10215, "unknown"), (10243, "unknown"), (10566, "unknown"),
    (10616, "unknown"), (10617, "unknown"), (10621, "unknown"),
    (10626, "unknown"), (10628, "unknown"), (10629, "unknown"),
    (11110, "unknown"), (11111, "vce"), (11211, "memcached"),
    (11235, "unknown"), (11300, "beanstalkd"), (11967, "unknown"),
    (12000, "cce4x"), (12174, "unknown"), (12265, "unknown"),
    (12345, "netbus"), (13456, "unknown"), (13722, "netbackup"),
    (13782, "netbackup2"), (13783, "vopied"), (14000, "scotty-ft"),
    (14238, "unknown"), (14441, "unknown"), (14442, "unknown"),
    (15000, "hydap"), (15002, "unknown"), (15003, "unknown"),
    (15004, "unknown"), (15660, "unknown"), (15742, "unknown"),
    (16000, "fmsas"), (16001, "unknown"), (16012, "unknown"),
    (16016, "unknown"), (16018, "unknown"), (16080, "osxwebadmin"),
    (16113, "unknown"), (16992, "amt-soap-http"), (16993, "amt-soap-https"),
    (17877, "unknown"), (17988, "unknown"), (18040, "unknown"),
    (18101, "unknown"), (18988, "unknown"), (19101, "unknown"),
    (19283, "unknown"), (19315, "unknown"), (19350, "unknown"),
    (19780, "unknown"), (19801, "unknown"), (19842, "unknown"),
    (20000, "dnp"), (20005, "btx"), (20031, "unknown"),
    (20221, "unknown"), (20222, "ipulse-ics"), (20828, "unknown"),
    (21571, "unknown"), (22939, "unknown"), (23502, "unknown"),
    (24444, "unknown"), (24800, "synergy"), (25734, "unknown"),
    (25735, "unknown"), (26214, "unknown"), (27000, "flexlm"),
    (27017, "mongodb"), (27018, "mongodb-shard"), (27019, "mongodb-config"),
    (28017, "unknown"), (30000, "ndmps"), (30718, "unknown"),
    (30951, "unknown"), (31038, "unknown"), (31337, "elite"),
    (32768, "filenet-tms"), (32769, "filenet-rpc"), (32770, "filenet-nch"),
    (32771, "sometimes-rpc5"), (32772, "sometimes-rpc7"), (32773, "sometimes-rpc9"),
    (32774, "sometimes-rpc11"), (32775, "sometimes-rpc13"), (32776, "sometimes-rpc15"),
    (32777, "sometimes-rpc17"), (32778, "sometimes-rpc19"), (32779, "sometimes-rpc21"),
    (32780, "sometimes-rpc23"), (32781, "unknown"), (32782, "unknown"),
    (32783, "unknown"), (32784, "unknown"), (32785, "unknown"),
    (33354, "unknown"), (33899, "unknown"), (34571, "unknown"),
    (34572, "unknown"), (34573, "unknown"), (35500, "unknown"),
    (38292, "unknown"), (40193, "unknown"), (40911, "unknown"),
    (41511, "unknown"), (42510, "unknown"), (44176, "unknown"),
    (44442, "unknown"), (44443, "unknown"), (44501, "unknown"),
    (45100, "unknown"), (48080, "unknown"), (49152, "unknown"),
    (49153, "unknown"), (49154, "unknown"), (49155, "unknown"),
    (49156, "unknown"), (49157, "unknown"), (49158, "unknown"),
    (49159, "unknown"), (49160, "unknown"), (49161, "unknown"),
    (49163, "unknown"), (49165, "unknown"), (49167, "unknown"),
    (49175, "unknown"), (49176, "unknown"), (49400, "compaqdiag"),
    (49999, "unknown"), (50000, "ibm-db2"), (50001, "unknown"),
    (50002, "unknown"), (50003, "unknown"), (50006, "unknown"),
    (50300, "unknown"), (50389, "unknown"), (50500, "unknown"),
    (50636, "unknown"), (50800, "unknown"), (51103, "unknown"),
    (51493, "unknown"), (52673, "unknown"), (52822, "unknown"),
    (52848, "unknown"), (52869, "unknown"), (54045, "unknown"),
    (54328, "unknown"), (55055, "unknown"), (55056, "unknown"),
    (55555, "unknown"), (55600, "unknown"), (56737, "unknown"),
    (56738, "unknown"), (57294, "unknown"), (57797, "unknown"),
    (58080, "unknown"), (60020, "unknown"), (60443, "unknown"),
    (61532, "unknown"), (61900, "unknown"), (62078, "unknown"),
    (63331, "unknown"), (64623, "unknown"), (64680, "unknown"),
    (65000, "unknown"), (65129, "unknown"), (65389, "unknown"),
];

/// Start all protocol handlers with async write buffer
pub async fn start_all(config: &Config, event_bus: EventBus, db: Database, geoip: SharedGeoIp, write_tx: WriteSender) -> Result<()> {
    let config = Arc::new(config.clone());
    let event_bus = Arc::new(event_bus);
    let _db = Arc::new(db.clone()); // Keep for future use, handlers use write_tx

    // Determine max ports from config (0 means all ports)
    let max_ports = if config.server.max_ports == 0 {
        TCP_PORTS.len()
    } else {
        config.server.max_ports
    };

    let ports_to_start = &TCP_PORTS[..max_ports.min(TCP_PORTS.len())];
    
    if ports_to_start.len() < TCP_PORTS.len() {
        info!("Starting {} of {} ports (set server.max_ports to change)", ports_to_start.len(), TCP_PORTS.len());
    }

    // Start TCP listeners for each port (skip 80/443 as those will be web server)
    for (port, service) in ports_to_start {
        let port = *port;
        let service = service.to_string();
        let config = config.clone();
        let event_bus = event_bus.clone();
        let write_tx = write_tx.clone();
        let geoip = geoip.clone();

        tokio::spawn(async move {
            match service.as_str() {
                "ssh" | "ssh-alt" => {
                    if let Err(e) = ssh::start(port, config, event_bus, write_tx, geoip).await {
                        tracing::debug!("SSH handler on port {} failed: {}", port, e);
                    }
                }
                "ftp" => {
                    if let Err(e) = ftp::start(port, config, event_bus, write_tx, geoip).await {
                        tracing::debug!("FTP handler on port {} failed: {}", port, e);
                    }
                }
                "telnet" => {
                    if let Err(e) = telnet::start(port, config, event_bus, write_tx, geoip).await {
                        tracing::debug!("Telnet handler on port {} failed: {}", port, e);
                    }
                }
                _ => {
                    if let Err(e) = tcp::start(port, &service, config, event_bus, write_tx, geoip).await {
                        tracing::debug!("{} handler on port {} failed: {}", service, port, e);
                    }
                }
            }
        });
    }

    // ICMP handler (optional, requires CAP_NET_RAW)
    let event_bus_icmp = event_bus.clone();
    let write_tx_icmp = write_tx.clone();
    let geoip_icmp = geoip.clone();
    tokio::spawn(async move {
        if let Err(e) = icmp::start(event_bus_icmp, write_tx_icmp, geoip_icmp).await {
            tracing::debug!("ICMP handler failed: {}", e);
        }
    });

    info!("Started {} protocol handlers with async write buffer", ports_to_start.len());
    Ok(())
}

