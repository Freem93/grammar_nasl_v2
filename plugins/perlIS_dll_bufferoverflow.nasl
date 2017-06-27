#
# This script was written by Drew Hintz ( http://guh.nu )
# 
# It is based on scripts written by Renaud Deraison and  HD Moore
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (12/28/10)

include("compat.inc");

if(description)
{
 script_id(10811);
 script_version ("$Revision: 1.24 $");
 script_name(english:"ActivePerl perlIS.dll Remote Buffer Overflow");
 script_cve_id("CVE-2001-0815");
 script_bugtraq_id(3526);
 script_osvdb_id(678);
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute arbitrary code on the remote
system." );
 script_set_attribute(attribute:"description", value:
"An attacker can run arbitrary code on the remote computer.
This is because the remote IIS server is running a version of
ActivePerl prior to 5.6.1.630 and has the Check that file
exists option disabled for the perlIS.dll." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/3659" );
 script_set_attribute(attribute:"solution", value:
"Either upgrade to a version of ActivePerl more
recent than 5.6.1.629 or enable the Check that file exists option.
To enable this option, open up the IIS MMC, right click on a (virtual)
directory in your web server, choose Properties, 
click on the Configuration... button, highlight the .plx item,
click Edit, and then check Check that file exists.

More Information: http://www.securityfocus.com/bid/3526" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/11/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/11/15");
 script_cvs_date("$Date: 2011/03/17 01:57:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Determines if arbitrary commands can be executed thanks to ActivePerl's perlIS.dll");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001-2011 H D Moore & Drew Hintz ( http://guh.nu )");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

function check(req)
{
 local_var r;

 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if(r == NULL)exit(0);

 if ("HTTP/1.1 500 Server Error" >< r &&
     ("The remote procedure call failed." >< r ||
      "<html><head><title>Error</title>" >< r))
 {
   security_hole(port:port);
   return(1);
 }
 return(0);
}

dir[0] = "/scripts/";
dir[1] = "/cgi-bin/";
dir[2] = "/";

for(d = 0; dir[d]; d = d + 1)
{
	url = string(dir[d], crap(660), ".plx"); #by default perlIS.dll handles .plx
	if(check(req:url))exit(0);

	url = string(dir[d], crap(660), ".pl");
	if(check(req:url))exit(0);
}
