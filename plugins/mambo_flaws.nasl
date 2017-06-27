#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16315);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/02/11 21:07:49 $");

 script_cve_id("CVE-2003-1204");
 script_bugtraq_id(6571, 6572);
 script_osvdb_id(
  7495,
  7496,
  7497,
  7498,
  7499,
  7500,
  7501,
  7502,
  7503,
  7504,
  7505,
  7506,
  7507,
  7508
 );

 script_name(english:"Mambo Site Server Multiple Vulnerabilities");
 script_summary(english:"Determine if Mambo Site Server is vulnerable to xss attack and remote flaw");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"An attacker may use the installed version of Mambo Site Server to
perform a cross-site scripting attack on this host or execute
arbitrary code through the gallery image uploader under the
administrator directory." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/306206" );
 script_set_attribute(attribute:"solution", value:"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/01/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_dependencies("mambo_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/mambo_mos");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 url = string(dir, "/themes/mambosimple.php?detection=detected&sitename=</title><script>foo</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 
 if ( '<a href="?detection=detected&sitename=</title><script>foo</script>' >< buf )
 {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}
