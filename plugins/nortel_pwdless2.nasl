#
# This script was written by Victor Kirhenshtein <sauros@iname.com>
# Based on cisco_675.nasl by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/2/09)
# - add global_settings/supplied_logins_only (6/22/15)

include("compat.inc");

if (description)
{
   script_id(10529);
   script_version("$Revision: 1.18 $");
   script_cvs_date("$Date: 2015/09/24 16:49:07 $");
   script_osvdb_id(428);

   script_name(english:"Nortel Networks Router Unpassworded Account (User Level)");
   script_summary(english:"Logs into the remote Nortel Networks (Bay Networks) router");

   script_set_attribute(attribute:"synopsis", value:"The remote Telnet service can be accessed without a password.");
   script_set_attribute(attribute:"description", value:
"The remote Telnet service has an account named 'User' that does not
have a password. 

This issue is known to affect Nortel Networks (formerly Bay Networks)
routers.  And it could allow an attacker to access the router,
reconfigure it to block access, and prevent its use.");
   script_set_attribute(attribute:"solution", value:"Set a password for the account.");
   script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

   script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/01");
   script_set_attribute(attribute:"plugin_publication_date", value:"2000/10/06");

   script_set_attribute(attribute:"plugin_type", value:"remote");
   script_end_attributes();

   script_category(ACT_GATHER_INFO);
   script_copyright(english:"This script is Copyright (C) 2000-2015 Victor Kirhenshtein");
   script_family(english:"Misc.");

   script_require_ports(23);
   script_exclude_keys("global_settings/supplied_logins_only");
   exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include('telnet_func.inc');

port = 23;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

buf = get_telnet_banner(port:port);
if (!buf) exit(0, "The Telnet service listening on port "+port+" did not return a banner.");
if ("Bay Networks" >!< buf ) exit(0, "The Telnet service listening on port "+port+" is not from a Bay Networks device.");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

buf = telnet_negotiate(socket:soc);
if ("Bay Networks" >< buf)
{
  if ("Login:" >< buf)
  {
    data = string("User\r\n");
    send(socket:soc, data:data);
    buf2 = recv(socket:soc, length:1024);
    if ("$" >< buf2)
    {
      security_hole(port);
      exit(0);
    }
    else exit(0, "The Telnet service listening on port "+port+" is not affected.");
  }
  else exit(0, "The Telnet service listening on port "+port+" does not prompt for a login.");
}
else exit(0, "Failed to negotiate a connection with the Telnet service listening on port "+port+".");
