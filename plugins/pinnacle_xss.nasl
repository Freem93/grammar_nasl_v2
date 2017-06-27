#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15485);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_cve_id("CVE-2004-1700");
  script_bugtraq_id(11415);
  script_osvdb_id(10726);

  script_name(english:"Pinnacle ShowCenter SettingsBase.php Skin Parameter XSS");
  script_summary(english:"Checks skin XSS in Pinnacle ShowCenter");

  script_set_attribute(attribute:"synopsis", value:"A remote web application is vulnerable to cross-site scripting.");
  script_set_attribute(attribute:"description", value:
"The remote host runs the Pinnacle ShowCenter web-based interface.

The remote version of this software is vulnerable to cross-site
scripting attack due to a lack of sanity checks on skin parameter in
the SettingsBase.php script.

With a specially crafted URL, an attacker can cause arbitrary code
execution resulting in a loss of integrity.");
  script_set_attribute(attribute:"solution", value:"Upgrade to the newest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");

  script_dependencie("cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8000);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP.");
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0, "The web server on port "+port+" is prone to XSS.");

buf = http_get(item:"/ShowCenter/SettingsBase.php?Skin=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(1, "The web server on port "+port+" did not respond.");

if(egrep(pattern:"<script>foo</script>", string:r))
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
