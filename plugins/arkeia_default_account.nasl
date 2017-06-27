#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17157);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2005-0496");
 script_bugtraq_id(12600);
 script_osvdb_id(15130);

 script_name(english:"Knox Arkeia Network Backup Agent Default Account");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote backup service allows arbitrary file access." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Arkeia Network Backup agent, used for
backups of the remote host. 

The remote version of this agent contains a default account that may
allow an attacker to gain read/write arbitrary files on the remote
system with the privileges of the Arkeia daemon, usually root." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/391000" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/20");
 script_cvs_date("$Date: 2012/03/15 19:27:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Determines if the Arkeia Default account is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_require_ports(617);
 exit(0);
}


port = 617;
if  ( ! get_port_state(port) ) exit(0);

hello = raw_string(0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x01, 0x00, 0x00, 0x7f, 0x41, 0x52, 0x4b, 0x41, 0x44, 0x4d, 0x49, 0x4e, 0x00, 0x72,
0x6f, 0x6f, 0x74, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x00, 0x00, 0x34, 0x2e, 0x33, 0x2e, 0x30,
0x2d, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

soc = open_sock_tcp(port);
if ( ! soc ) exit( 0 );
send(socket:soc, data:hello);

r = recv(socket:soc, length:29);
if ( strlen(r) != 29 ) exit(0);

pkt = raw_string(0x00, 0x73, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x0c, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);


send(socket:soc, data:pkt);

r = recv(socket:soc, length:32);
if ( strlen(r) != 32 ) exit(0);


pkt = raw_string ( 0, 0x61, 0, 4, 0, 1, 0, 0x15, 0, 0) + "15398" + raw_string(0) + "EN" + crap(data:raw_string(0), length:11);

send(socket:soc, data:pkt);

r = recv(socket:soc, length:8);
if ( strlen(r) != 8 ) exit(0);

pkt = raw_string(0, 0x62, 0x00, 0x01, 0x00, 0x02, 0x00) + "%ARKADMIN_GET_CLIENT_INFO" + raw_string(0) + "2" + crap(length:11, data:raw_string(0));
send(socket:soc, data:pkt);
r = recv(socket:soc, length:8);
if ( strlen(r) != 8 ) exit(0);

pkt  = raw_string(0x00, 0x63, 0x00, 0x04, 0x00, 0x03, 0x00, 0x11, 0x30, 0x00, 0x31, 0x00, 0x32) + crap(length:12, data:raw_string(0));
send(socket:soc, data:pkt);
r = recv(socket:soc, length:65535);
str = strstr(r, "Arkeia Network Backup ");
if ( ! str ) exit(0);
for ( i = 0; ord(str[i]) != 0 ; i ++)
{
 version += str[i];
}

version_num = ereg_replace(pattern:"Arkeia Network Backup ([0-9.]*)", replace:"\1", string:version);

set_kb_item(name:"arkeia-client/" + port, value:version_num);

report = string(
	"The remote version of the software is : ", version ,
	"\n");

security_hole(port:port, extra:report);
