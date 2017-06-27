#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15850);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_cve_id("CVE-2004-1202");
  script_bugtraq_id(11765);
  script_osvdb_id(12134);

  script_name(english:"phpCMS parser.php file Parameter XSS");
  script_summary(english:"Checks phpCMS XSS");

  script_set_attribute(attribute:"synopsis", value:"A remote web application is vulnerable to cross-site scripting.");
  script_set_attribute(attribute:"description", value:
"The remote host runs phpCMS, a content management system written in
PHP.

This version is vulnerable to cross-site scripting due to a lack of
sanitization of user-supplied data in parser.php script. Successful
exploitation of this issue may allow an attacker to execute malicious
script code on a vulnerable server.");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.1pl1 or newer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpcms:phpcms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0, "Port "+port+" is closed.");
if ( ! can_host_php(port:port) )
 exit(0, "The web server on port "+port+" does not support PHP scripts.");

if ( get_kb_item("www/" + port + "/generic_xss") )
 exit(0, "The web server on port "+port+" is prone to XSS.");

buf = http_get(item:"/parser/parser.php?file=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:0);
if( r == NULL )exit(1, "The web server on port "+port+" failed to respond.");

if(
egrep(pattern:"^HTTP/1\.[01] +200 ", string:r) &&
egrep(pattern:"<script>foo</script>", string:r)
)
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
