#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15462);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2004-2193");
 script_bugtraq_id(11359);
 script_osvdb_id(10640);
 
 script_name(english:"CjOverkill trade.php Multiple Method XSS");
 script_summary(english:"Check CjOverkill version");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server runs a CGI application that is affected by a
cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote server runs a version of CjOverkill, a free traffic trading 
script that is as old as or older than version 4.0.3.

The remote version of this software is affected by a cross-site 
scripting vulnerability in the script 'trade.php'. This issue is due 
to a failure of the application to properly sanitize user-supplied 
input.

As a result of this vulnerability, it is possible for a remote 
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication 
credentials as well as other attacks.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Oct/296");
 script_set_attribute(attribute:"solution", value:"Upgrade to version 4.0.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/12");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cjoverkill:cjoverkill");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if(!port) exit(0);
if(!can_host_php(port:port))exit(0);

if(get_port_state(port))
{
 buf = http_get(item:"/trade.php", port:port);
 r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"<title>CjOverkill Version ([0-3]\.|4\.0\.[0-3][^0-9])</title>", string:r))
 {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}
