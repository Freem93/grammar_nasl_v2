#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added a source reference link on www.securiteam.com

include("compat.inc");

if (description)
{
 script_id(10322);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/11/01 19:59:57 $");

 script_bugtraq_id(6599);
 script_osvdb_id(57211);

 script_name(english:"Xitami Web Server Administration Port Remote Overflow");
 script_summary(english:"Xitami buffer overflow");

 script_set_attribute(attribute:"synopsis", value:"The remote web server has a remote buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a vulnerable version of the Xitami web
server. An attacker could exploit this by sending a lot of data to TCP
port 81. This could lead to the execution of arbitrary code in the
context of the web server, or create a denial of service.");
 #https://web.archive.org/web/20010201014700/http://archives.neohapsis.com/archives/ntbugtraq/1999-q3/0315.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ca7bf65");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of the software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/30");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports(81);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 81;
if (! get_port_state(port)) exit(0);

data = crap(8192);
soc = open_sock_tcp(port);
if(! soc) exit(0);

send(socket:soc, data:data);
close(soc);

for (i = 0; i < 3; i ++)
{
  sleep(i);
  soc2 = open_sock_tcp(port);
  if (soc2) { close(soc2); exit(0); }
}
if (!soc2) security_hole(port);
