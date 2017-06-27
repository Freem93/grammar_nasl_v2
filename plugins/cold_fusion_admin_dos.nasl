#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
# Update - 13.9.01 - Felix Huber <huberfelix@webtopia.de>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10581);
 script_bugtraq_id(1314);
 script_osvdb_id(3399);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2000-0538");

 script_name(english:"Cold Fusion Administration Page Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"A denial of service vulnerability exists within the Allaire ColdFusion
web application server (version 4.5.1 and earlier) which allows an 
attacker to overwhelm the web server and deny legitimate web page 
requests.

By downloading and altering the login HTML form, an attacker can send 
overly large passwords (>40,0000 chars) to the server, causing it to
stop responding." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jun/109" );
 script_set_attribute(attribute:"solution", value:
"Use HTTP basic authentication to restrict access to this page or
remove it entirely if remote administration is not a requirement." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/12/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/06/07");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the presence of /cfide/administrator/index.cfm";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Matt Moore");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 # CFIDE will work with CF Linux also
 req = http_get(item:"/CFIDE/administrator/index.cfm",
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if("PasswordProvided" >< r && "cf50" >!< r)	
 	security_warning(port);

}
