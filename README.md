CyberCAPTOR Server
==============

[Cyber seCurity Attack graPh moniTORing - Server]

CyberCAPTOR is an implementation of the Cyber Security Generic Enabler, the future developments of the [Security Monitoring GE](http://catalogue.fiware.org/enablers/security-monitoring).

NOTE : This repository was adapted to fit the needs of the DOCTOR and 5G-ENSURE projects. Namely, the container now embeds a monolithic version of CyberCAPTOR, with the API server, web client and the cyber-data-extract preprocessor. In order to complete the installation (e.g. to build the Docker container), one must initialize the ```cyber-data-extract``` and -```cybercaptor-client``` repositories as submodules of the ```cybercaptor-server``` repository.

## Table of Contents

- [CyberCAPTOR Server](#cybercaptor-server)
	- [Development Version Installation](#development-version-installation)
		- [Prerequisite](#prerequisite)
		- [Build](#build)
		- [Installation](#installation)
		- [Test](#test)
	- [Docker Version Deployment](#docker-version-deployment)
		- [Build container (optional)](#build-container-optional)
		- [Run container](#run-container)
	- [Debugging](#debugging)
		- [Main logs files](#main-logs-files)
	- [API](#api)
		- [API usage](#api-usage)
			- [Version API calls](#version-api-calls)
			- [Initialization calls](#initialization-calls)
			- [Attack graph, attack paths and remediation calls](#attack-graph-attack-paths-and-remediation-calls)
	- [Developers](#developers)

## Development Version Installation

### Prerequisite
- git-lfs
- Ubuntu
- Java 1.7
- Apache Tomcat 7
- Apache Maven 2
- Python 2
- [XSB](http://xsb.sourceforge.net/)
- [MulVAL](http://www.arguslab.org/mulval.html)

### Build

1) Get sources from Github
```
git clone https://github.com/DOCTOR-ANR/cybercaptor-server.git
cd cybercaptor-server
git submodule init
git submodule update
```

2) Build the project
```
make clean
make
```

### Installation

1) Deploy the .war into tomcat.

Using command line

```
cp ./target/cybercaptor-server*.war /var/lib/tomcat7/webapps/cybercaptor-server.war
```

This can also be done using the tomcat GUI manager, or with Maven's tomcat7 plugin.

2) Link the configuration and scripts repertory and fix permissions

```
sudo ln -s `pwd`/configuration-files /usr/share/tomcat7/.remediation
chmod -R o+rw ./configuration-files/
sudo chown -R tomcat7:tomcat7 /usr/share/tomcat7/
cd .. #Go in the parent folder of cybercaptor-server
```
```
(or make install)
```

3) Copy and edit the configuration file

```
cp ./configuration-files/config.properties.sample ./configuration-files/config.properties
vim ./configuration-files/config.properties

```

For more details, read the documentation [Installation And adminsitration Manual](./doc/InstallationAndAdministrationManual.md).

## Docker Version Deployment

### Build container (optional)

1) Get sources from Github
```
git clone https://github.com/DOCTOR-ANR/cybercaptor-server.git
cd cybercaptor-server
git submodule init
git submodule update
```

2) Build the container
```
docker build -t cybercaptor-server .
```

### Run container

If you want to run the server in foreground, launch the following command:

```
docker run --rm --name cybercaptor-server -p 8080:8080 -p 8000:8000 cybercapt
```

If you want to run the server in background, launch the following command:

```
docker run -d --name cybercaptor-server -p 8080:8080 -p 8000:8000 doctoranr/cybercaptor
```

Then, the application can be accessed at http://localhost:8080/cybercaptor-server/.
The web interface can be accessed at http://localhost:8000/

### Test

Go on URL : http://localhost:8080/cybercaptor-server/rest/json/initialize

If the result is ```{"status":"Loaded"}```, the application has been properly built and installed.

For more details, read the documentation [Installation And adminsitration Manual](./doc/InstallationAndAdministrationManual.md).

## Debugging

### Main logs files
- ``` /var/log/tomcat7/catalina.out ```
- ``` `pwd`/configuration-files/tmp/xsb_log.txt ```
- ``` `pwd`/configuration-files/tmp/input-generation.log ```

## API

### API usage

#### Version API calls

To use the CyberCAPTOR server API, the first call to test that the server is available is

```
curl http://localhost:8080/cybercaptor-server/rest/version/detailed
```

which should returns something like

```
{"version":"4.4"}
```

#### Initialization calls

Before using the API to manipulate the attack graph, the attack paths, and the remediations,
the first call that needs to be done is

```
curl http://localhost:8080/cybercaptor-server/rest/json/initialize
```

which loads the topology, generates the attack graph with MulVAL and computes the attack paths.

Note that the server does not handle multiple simultaneous sessions : An initialization call overwrites the current state of the server.

It is also possible to load the topology from an XML file, or a XML string containing the XML network topology, using the POST method of the `/rest/json/initialize` call :

Using a XML String:

```
curl -H "Content-Type: application/xml" -X POST -d '<topology><machine><name>linux-user-1</name><security_requirement>7</security_requirement><interfaces><interface><name>eth0</name><ipaddress>192.168.1.111</ipaddress><vlan><name>user-lan</name><label>user-lan</label></vlan></interface></interfaces><routes><route><destination>0.0.0.0</destination><mask>0.0.0.0</mask><gateway>192.168.1.111</gateway><interface>eth0</interface></route></routes></machine><machine><name>linux-user-2</name><security_requirement>30</security_requirement><interfaces><interface><name>eth0</name><ipaddress>192.168.1.112</ipaddress><vlan><name>user-lan</name><label>user-lan</label></vlan></interface></interfaces><services><service><name>mdns</name><ipaddress>192.168.1.112</ipaddress><protocol>udp</protocol><port>5353</port><vulnerabilities><vulnerability><type>remoteExploit</type><cve>CVE-2007-2446</cve><goal>privEscalation</goal><cvss>10.0</cvss></vulnerability></vulnerabilities></service></services><routes><route><destination>0.0.0.0</destination><mask>0.0.0.0</mask><gateway>192.168.1.111</gateway><interface>eth0</interface></route></routes></machine></topology>' http://localhost:8080/cybercaptor-server/rest/json/initialize
```

Using a XML file:

```
curl -X POST  -H "Content-Type: multipart/form-data"  -F "file=@./topology.xml" http://localhost:8080/cybercaptor-server/rest/json/initialize
```

#### Attack graph, attack paths and remediation calls

Then, the calls to get the attack paths, attack graph or remediations can be used:

Get the number of attack paths:

```
curl http://localhost:8080/cybercaptor-server/rest/json/attack_path/number
```

Get the attack path 0:

```
curl http://localhost:8080/cybercaptor-server/rest/json/attack_path/0
```

Get the attack graph

```
curl http://localhost:8080/cybercaptor-server/rest/json/attack_graph
```

Get the remediations for attack path 0:

```
curl http://localhost:8080/cybercaptor-server/rest/json/attack_path/0/remediations
```

Get the XML network topology (useful for backups):

```
curl http://localhost:8080/cybercaptor-server/rest/json/topology
```

For more details, please refer to [User & Programmers manual](./doc/UserAndProgrammersManual.md#user-guide).

## Developers

If you want to participate to the development of CyberCAPTOR-Server, all contributions are welcome.

