#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10009);
 script_version("$Revision: 1.48 $");
 script_cvs_date("$Date: 2014/05/25 01:17:39 $");

 script_cve_id("CVE-1999-0789");
 script_bugtraq_id(679);
 script_osvdb_id(9);

 script_name(english:"AIX FTPd libc Library Remote Buffer Overflow");
 script_summary(english:"Checks for a buffer overflow in the remote FTPd");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote FTP server by issuing the command :

 CEL aaaa[...]aaaa

This problem is known as the 'AIX FTPd' overflow and may allow the
remote user to easily gain access to the root (super-user) account on
the remote system.");
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/1089.html");
 script_set_attribute(attribute:"solution", value:
"If you are using AIX FTPd, then read IBM's advisory number
ERS-SVA-E01-1999:004.1, or contact your vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/09/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/09/30");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

if (get_kb_item("ftp/"+port+"/msftpd") || get_kb_item("ftp/"+port+"/vxftpd"))
  exit(0);

banner = get_ftp_banner(port: port);
if ( ! banner ) exit(1, "No FTP banner on port "+port+".");

if ( ! egrep(pattern:".*FTP server .Version 4\.", string:banner) ) exit(0);

if(safe_checks())
{

 if(egrep(pattern:".*FTP server .Version 4\.3.*",
   	 string:banner)){
  	 security_hole(port:port, extra:
"Nessus reports this vulnerability using only information
that was gathered. Use caution when testing without safe checks
enabled." );
	 }
 exit(0);
}

get_kb_item_or_exit("ftp/"+port+"/vxworks");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Cannot connect to TCP port "+port+".");

  buf = ftp_recv_line(socket:soc);
  if(!buf){
 	close(soc);
	exit(0);
	}

  buf = 'CEL a\r\n';
  send(socket:soc, data:buf);
  r = ftp_recv_line(socket:soc);
  if(!r)exit(0);
  buf = strcat('CEL ', crap(2048), '\r\n');
  send(socket:soc, data:buf);
  b = ftp_recv_line(socket:soc);
  if(!b)security_hole();
  ftp_close(socket: soc);
