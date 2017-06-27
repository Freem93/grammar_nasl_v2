#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18259);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2005-1612", "CVE-2005-1613");
 script_bugtraq_id(13624, 13625);
 script_osvdb_id(16623, 16624);
 
 script_name(english:"OpenBB < 1.0.9 Multiple Vulnerabilities");
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running OpenBB, a forum management system 
written in PHP.

The remote version of this software is vulnerable to cross-site 
scripting attacks, and SQL injection flaws.

Using a specially crafted URL, an attacker may execute arbitrary 
commands against the remote SQL database or use the remote server to set
up a cross-site scripting attack." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.0.9 of this software or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/12");
 script_cvs_date("$Date: 2015/02/11 21:07:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Detects openBB version");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if (ereg(pattern:'Powered by <a href="http://www.openbb.com/" target="_blank">Open Bulletin Board</a>[^0-9]*1\\.(0[^0-9]|0\\.[0-8][^0-9])<br>', string:res))
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}
