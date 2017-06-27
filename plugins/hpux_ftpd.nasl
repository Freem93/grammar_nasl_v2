#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10490);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");

 script_cve_id("CVE-2000-0699");
 script_bugtraq_id(1560);
 script_osvdb_id(389);

 script_name(english:"HP-UX FTP Daemon PASS Command Remote Format String");
 script_summary(english:"Checks if the remote ftp sanitizes the PASS command");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a format string stack overwrite
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote ftp server does not sanitize properly the argument of the
PASS command it receives for anonymous accesses.

It may be possible for a remote attacker to gain shell access.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Aug/79");
 script_set_attribute(attribute:"solution", value:"Patches are available from the vendor.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/08/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/08/07");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_kibuv_worm.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner || " FTP server" >!< banner ) exit(0);

# Connect to the FTP server
soc = open_sock_tcp(port);
ftpport = port;
if (! soc) exit(1);

 r = ftp_recv_line(socket:soc);
 if(!strlen(r))exit(1);


 req = 'USER ftp\r\n';
 send(socket:soc, data:req);

 r = ftp_recv_line(socket:soc);
 if(!strlen(r))exit(0);


 req = 'PASS %.2048d\r\n';
 send(socket:soc, data:req);
 r = ftp_recv_line(socket:soc);


 if(egrep(string:r, pattern:"^230 .*"))
 {
  req = 'HELP\r\n';
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  if(!r)security_hole(port);
 }
 close(soc);
