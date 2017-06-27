#
# Copyright 2001 by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, changed family (4/13/2009)

include("compat.inc");

if(description)
{
 script_id(11004);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-1999-0508");
 script_osvdb_id(824);

 script_name(english:"Ipswitch WhatsUp Gold Default Admin Account");
 script_summary(english:"WhatsUp Gold Default Admin Account");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a default set of administrative
credentials.");
 script_set_attribute(attribute:"description", value:
"This WhatsUp Gold server still has the default password for the admin
user account.  An attacker can use this account to probe other systems
on the network and obtain sensitive information about the monitored
systems.");
 script_set_attribute(attribute:"solution", value:
"Login to this system and either disable the admin account or assign
it a difficult to guess password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
 script_cvs_date("$Date: 2016/02/04 22:38:29 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2016 Digital Defense Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

if (supplied_logins_only) exit(0, "The 'Do not log in with user accounts not specified in the policy' preference setting is enabled.");

soc = http_open_socket(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");

req = string("GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46YWRtaW4K\r\n\r\n");
send(socket:soc, data:req);
buf = http_recv(socket:soc);
http_close_socket(soc);

if (!isnull(buf) && "Whatsup Gold" >< buf && "Unauthorized User" >!< buf)
{
 security_hole(port:port);
}
