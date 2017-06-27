#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting, family change (9/3/09)

include("compat.inc");

if (description)
{
 script_id(11218);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/05/09 20:31:00 $");

 # script_cve_id("CVE-MAP-NOMATCH");
 script_osvdb_id(561);

 script_name(english:"Tomcat /status Information Disclosure");
 script_summary(english:"Makes a request.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(
   attribute:"description",
   value:
"Requesting the URI '/status' gives information about the currently
running instance of the remote web server (most likely Apache Tomcat). 
It also allows anybody to reset the current statistics. A remote
attacker can use this information to mount further attacks."
 );
 script_set_attribute(
   attribute:"solution",
   value:
"Disable this feature if it is not being used. Otherwise, restrict
access to it."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/03");

 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 StrongHoldNet");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0, "Port "+port+" is not open.");

buffer = http_get(item:"/status", port:port);
data = http_keepalive_send_recv(port:port, data:buffer);
if( ("Status information for" >< data) && ("<a href='jkstatus?scoreboard.reset'>reset</a>" >< data) )
{
 security_warning(port);
 exit(0);
}
exit(0, "The web server listening on port "+port+" is not affected.");
