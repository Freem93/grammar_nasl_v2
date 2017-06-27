#
# (C) Tenable Network Security, Inc.
#

# - modified by Josh Zlatin-Amishav to support newer versions of the product.


include("compat.inc");

if (description)
{
 script_id(15615);
 script_version("$Revision: 1.17 $");
 
 script_name(english:"McAfee IntruShield Management Console Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running McAfee IntruShield Management Console." );
 script_set_attribute(attribute:"description", value:
"If an attacker can log into the IntruShield Management Console on the
remote host, the attacker will have the ability to modify sensor 
configuration." );
 # http://web.archive.org/web/20051104064722/http://www.mcafee.com/us/products/mcafee/network_ips/category.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42dad386" );
 script_set_attribute(attribute:"solution", value:
"Configure your firewall to prevent unauthorized hosts from
connecting to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/03");
 script_cvs_date("$Date: 2013/06/04 22:17:23 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 summary["english"] = "Detect McAfee IntruShield Management Console";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencies("httpver.nasl", "broken_web_server.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port))exit(0, "Port "+port+" is closed.");

req = http_get(item:"/intruvert/jsp/admin/Login.jsp", port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if (isnull(r)) exit(1, "The web server on port "+port+" failed to respond.");
if (
  egrep(pattern:"Copyright \(c\) 2001.* (Intruvert Network Inc|Networks Associates Technology)", string:r) &&
  egrep(pattern:"<(title|TITLE)>IntruShield Login", string:r)
) security_note(port);
