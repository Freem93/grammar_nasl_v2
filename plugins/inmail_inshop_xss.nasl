#
#  (C) Tenable Network Security, Inc.
#

#  Ref: Carlos Ulver

include("compat.inc");

if (description)
{
 script_id(15864);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");

 script_cve_id("CVE-2004-1196", "CVE-2004-1197");
 script_bugtraq_id(11758);
 script_osvdb_id(12155, 12156);

 script_name(english:"InMail/InShop inmail.pl / inshop.pl XSS");
 script_summary(english:"Checks XSS in InMail and InShop");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a Perl application that is affected
by a cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is using InMail/InShop, a web applications written in
Perl.

An implementation error in the validation of the user input
specifically in the script 'inmail.pl' in its 'acao' uri-argument and
'inshop.pl' in its 'screen' uri argument lead to an XSS vulnerability
allowing a user to create cross-site attacks, also allowing theft of
cookie-based authentication credentials.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Nov/340");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/30");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport", "www/PHP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if (!can_host_php(port:port))exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit ( 0 );

function check_dir(path)
{
 local_var	r;
 r = http_send_recv3(method: 'GET', item:string(path, "/inmail.pl?acao=<<script>foo</script>"), port:port);
 if (isnull(r)) exit(0);
 if (r[0] =~ "^HTTP/1\.[01] +200 " && "<script>foo</script>" >< r[2] )
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }

 r = http_send_recv3(method: 'GET', item:string(path, "/inshop.pl?screen=<script>foo</script>"), port:port);
 if (isnull(r)) exit(0);

 if (r[0] =~ "^HTTP/1\.[01] +200 " && "<script>foo</script>" >< r[2] )
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check_dir(path:dir);
}

