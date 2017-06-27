#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15566);
 script_version("$Revision: 1.17 $");
 
 script_cve_id("CVE-2004-1632");
 script_bugtraq_id(11516);
 script_osvdb_id(11124);

 script_name(english:"MoniWiki < 1.0.9 wiki.php XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected
by a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running MoniWiki, a wiki web application 
written in PHP.

The remote version of this software is vulnerable to cross-site 
scripting attacks, through the script 'wiki.php'.

With a specially crafted URL, an attacker can cause arbitrary code 
execution in users' browsers resulting in a loss of integrity." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Oct/981" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MoniWiki version 1.0.9 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/22");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Test for XSS flaw in MoniWiki");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 req = http_get(item:string(d, "/wiki.php/<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if("<wikiHeader>" >< res && "<script>foo</script>" >< res )
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}
