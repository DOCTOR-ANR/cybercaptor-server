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

