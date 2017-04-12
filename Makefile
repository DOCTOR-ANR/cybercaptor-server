default: cybercaptor

cybercaptor:
	mvn package

.PHONY:
clean:
	mvn clean
install:
	cp ./target/cybercaptor-server*.war /var/lib/tomcat7/webapps/cybercaptor-server.war
	test -h /usr/share/tomcat7/.remediation || ln -s `pwd`/configuration-files /usr/share/tomcat7/.remediation
	test -h /usr/share/tomcat7/python_scripts || ln -s `pwd`/src/main/python/ /usr/share/tomcat7/python_scripts
	chmod -R o+rw ./configuration-files/
	chown -R tomcat7:tomcat7 /usr/share/tomcat7/

ndn:
	touch configuration-files/inputs/aaa
	rm -v configuration-files/inputs/*
	cp -v configuration-files/inputs-ndn/* configuration-files/inputs/

r1:
	touch configuration-files/inputs/aaa
	rm -v configuration-files/inputs/*
	cp -v configuration-files/inputs-r1/* configuration-files/inputs/

r2:
	touch configuration-files/inputs/aaa
	rm -v configuration-files/inputs/*
	cp -v configuration-files/inputs-r2/* configuration-files/inputs/

remediation:
	touch configuration-files/inputs/aaa
	rm -v configuration-files/inputs/*
	cp -v configuration-files/inputs-remediation/* configuration-files/inputs/
