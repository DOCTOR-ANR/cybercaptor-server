
INSERT INTO `vulnerability` VALUES (1000001,'NDN-2017-0001','The NDN router doesn''t verify input data signature.',1000001);
INSERT INTO `vulnerability` VALUES (1000002,'NDN-2017-0002','The NDN router does not check incoming face of DATA packets.',1000002);
INSERT INTO `vulnerability` VALUES (1000003,'NDN-2017-0003','The NDN router does not check signature of received route announcements.',1000003);
INSERT INTO `vulnerability` VALUES (1000004,'NDN-2017-0004','Cache overflow allows remote code execution.',1000004);

INSERT INTO `cpe` VALUES (1000001,'cpe:/o:ndngroup:nfd:1.0');
INSERT INTO `cpe` VALUES (1000002,'cpe:/o:ndngroup:nfd:1.1');

INSERT INTO `cpe_vulnerability` VALUES (1000001,1000004);
INSERT INTO `cpe_vulnerability` VALUES (1000002,1000001);
INSERT INTO `cpe_vulnerability` VALUES (1000002,1000002);
INSERT INTO `cpe_vulnerability` VALUES (1000002,1000003);

INSERT INTO `cvss` VALUES (1000001,6.5,'SIGNATURE','MEDIUM','NONE','PARTIAL','COMPLETE','NONE');
INSERT INTO `cvss` VALUES (1000002,9.2,'PIT','LOW','PARTIAL','COMPLETE','COMPLETE','COMPLETE');
INSERT INTO `cvss` VALUES (1000003,10,'FIB','LOW','NONE','NONE','NONE','COMPLETE');
INSERT INTO `cvss` VALUES (1000004,8.3,'NETWORK','MEDIUM','COMPLETE','COMPLETE','COMPLETE','PARTIAL');

INSERT INTO `cwe` VALUES (1000001,'Improper verification of data signature.','The software does not properly verify the input data signature.','Base');
INSERT INTO `cwe` VALUES (1000002,'No verification of packet origin.','The software does not check incoming face of data packets.','Base');
INSERT INTO `cwe` VALUES (1000003,'No verification of route origin.','The software does not check route announcement signature.','Base');
INSERT INTO `cwe` VALUES (1000004,'Out-of-bound write.','Cache line written outside bounds','Base');

INSERT INTO `cwe_vulnerability` VALUES (1000001,1000001);
INSERT INTO `cwe_vulnerability` VALUES (1000002,1000002);
INSERT INTO `cwe_vulnerability` VALUES (1000003,1000003);
INSERT INTO `cwe_vulnerability` VALUES (1000004,1000004);

