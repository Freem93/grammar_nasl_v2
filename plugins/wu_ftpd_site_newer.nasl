#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10319);
 script_version ("$Revision: 1.40 $");
 script_cve_id("CVE-1999-0880");
 script_bugtraq_id(737);
 script_osvdb_id(249);
 
 script_name(english:"WU-FTPD SITE NEWER Command Memory Exhaustion DoS");
 script_summary(english:"Checks if the remote FTP server accepts the SITE NEWER command");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a denial of service vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"The remote WU-FTPD server accepts the command 'SITE NEWER'.
Some WU-FTPD servers (and probably others) are vulnerable
to a resource exhaustion where an attacker may invoke
this command to use all the memory available on the server." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/1999/Oct/212"
 );
 script_set_attribute(attribute:"solution",  value:
"Make sure that you are running the latest version of your FTP
server. If you are a WU-FTPD user, then make sure that you are
using at least version 2.6.0.

*** This warning may be irrelevant." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/10/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/10/19");
 script_cvs_date("$Date: 2016/11/15 19:41:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
		    
 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login", "ftp/wuftpd", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);
  
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");
include("global_settings.inc");
include("audit.inc");

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");


port = get_ftp_port(default: 21);

banner = get_ftp_banner(port: port);

if((!login) || safe_checks())
{
 if (report_paranoia < 2) audit(AUDIT_PARANOID);
 if(egrep(pattern:".*(wu|wuftpd)-((1\..*)|(2\.[0-5])).*",
 	 string:banner))security_warning(port);
  exit(0);
}


# Connect to the FTP server
soc = open_sock_tcp(port);
if (! soc) exit(1);

if (! ftp_authenticate(socket:soc, user:login, pass:pass))
  exit(1);

  # We are in
 
  port2 = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
  if(soc2)
  {
   c = 'SITE NEWER 19900101000000 \r\n';
   send(socket:soc, data:c);
   b = recv(socket:soc, length:3);
   if(b == "150")security_warning(port);
   close(soc2);
  }
  ftp_close(socket: soc);
