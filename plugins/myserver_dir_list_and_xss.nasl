#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18218);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2005-1658", "CVE-2005-1659");
 script_bugtraq_id(13579, 13578);
 script_osvdb_id(16237, 16238);

 script_name(english:"MyServer 0.8 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MyServer, an open source http server.
This version is vulnerable to a directory listing flaw and cross-site
scripting.

An attacker can execute a cross-site scripting attack, or gain 
knowledge of certain system information of the server." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/09");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:myserver:myserver");
script_end_attributes();

 script_summary(english:"Determine if MyServer is vulnerable to a XSS flaw");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

buf = http_get_cache(item:"/", port:port);
if( buf == NULL ) exit(0);

foreach d (cgi_dirs())
{
  if("<title>MyServer</title>" >< buf )
   {
    url = string(d, '/.../.../"onmouseover="<script>foo</script>"');
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
    if ( ! buf ) exit(0);
    if ( "<script>foo</script>" >< buf )
	{
	 security_warning(port);
	 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	 exit(0);
	}
   }
}

