#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10086);
 script_version ("$Revision: 1.35 $");
 script_cve_id("CVE-1999-0075");
 script_osvdb_id(5742);

 script_name(english:"WU-FTPD QUOTE PASV Forced Core Dump Information Disclosure");
 script_summary(english:"Issues a PASV command on connecting");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server fails to handle QUOTE PASV requests for logged
in users. An attacker can send a specially crafted requests to cause
the service to die and dump core. The core file contains the usernames
and passwords of all users." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?203721e9" );
 script_set_attribute(attribute:"solution", value:
"Upgrade your FTP server to the latest version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1996/10/14");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english:"FTP");
	       
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");
include("global_settings.inc");


port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (!banner) exit(1);
 
 # False positive in WinGate and FireWall 1
 if("WinGate Engine" >< banner)exit(0);
 if("Check Point FireWall-1" >< banner)exit(0);
 if("vsftp" >< banner) exit(0);
 
 if ( report_paranoia < 2 && "SunOS" >!< banner  ) exit(0);


soc = open_sock_tcp(port);
if (! soc) exit(1);

h = ftp_recv_line(socket:soc);
if (!h) exit(1);

if(egrep(pattern:"^220.*", string:h))
{
  send(socket:soc, data:'HELP\r\n');
  c = ftp_recv_line(socket:soc);
  if ( ! c ) exit(0);

  send(socket:soc, data: 'PASV\r\n');
  c = ftp_recv_line(socket:soc);
  if(!c)security_warning(port);
}
close(soc);
