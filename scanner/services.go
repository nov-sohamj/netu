package scanner

var knownServices = map[int]string{
	7: "echo", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
	25: "smtp", 43: "whois", 53: "dns", 67: "dhcp", 68: "dhcp",
	69: "tftp", 80: "http", 81: "http-alt", 88: "kerberos",
	110: "pop3", 111: "rpc", 113: "ident", 119: "nntp",
	123: "ntp", 135: "msrpc", 137: "netbios", 138: "netbios",
	139: "netbios", 143: "imap", 161: "snmp", 162: "snmp-trap",
	179: "bgp", 194: "irc", 389: "ldap", 443: "https",
	445: "smb", 465: "smtps", 500: "ike", 514: "syslog",
	515: "printer", 520: "rip", 530: "rpc", 543: "klogin",
	544: "kshell", 548: "afp", 554: "rtsp", 587: "submission",
	631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware",
	990: "ftps", 993: "imaps", 995: "pop3s", 1025: "msrpc",
	1080: "socks", 1194: "openvpn", 1433: "mssql", 1434: "mssql",
	1521: "oracle", 1701: "l2tp", 1723: "pptp", 1883: "mqtt",
	2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
	2181: "zookeeper", 3000: "dev-server", 3306: "mysql",
	3389: "rdp", 3690: "svn", 4443: "https-alt",
	5000: "dev-server", 5432: "postgres", 5672: "amqp",
	5900: "vnc", 5901: "vnc", 6379: "redis", 6443: "k8s-api",
	8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
	8443: "https-alt", 8880: "http-alt", 8888: "http-alt",
	9090: "prometheus", 9200: "elasticsearch", 9418: "git",
	27017: "mongodb",
}

// LookupService returns the common service name for a port, or empty string.
func LookupService(port int) string {
	return knownServices[port]
}
