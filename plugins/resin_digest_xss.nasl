#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46693);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id("CVE-2010-2032");
  script_bugtraq_id(40251);
  script_osvdb_id(64751);

  script_name(english:"Resin resin-admin/digest.php XSS");
  script_summary(english:"Tries to inject script code via digest.php");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is prone to cross-site
scripting attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Resin, an application server.

The 'resin-admin/digest.php' script included with the version of Resin
listening on the remote host fails to sanitize user input to the
'digest_realm' and/or 'digest_username' parameters before using it to
generate dynamic HTML output.

An attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/511341/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:caucho:resin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/resin");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8080);


# Unless we're paranoid, make sure the banner is from Resin.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "Unable to get the banner from web server on port "+port+".");
  if ("Resin" >!< banner) exit(1, "The web server on port "+port+" does not appear to be Resin.");
}


# Try to exploit the issues.
alert = string('">', "<script>alert('", SCRIPT_NAME, "')</script>");
cgi = '/digest.php';
dirs = make_list('resin-admin');

vuln = test_cgi_xss(
  port     : port,
  cgi      : cgi,
  dirs     : dirs,
  qs       : 'digest_attempt=1&digest_realm='+urlencode(str:alert)+'&digest_username[]=',
  pass_str : 'input name="digest_realm" size="50" value="'+alert,
  pass2_re : "<title>Resin Admin Login"
);
if (!vuln)
{
  vuln = test_cgi_xss(
    port     : port,
    cgi      : cgi,
    dirs     : dirs,
    qs       : 'digest_attempt=1&digest_username='+urlencode(str:alert),
    pass_str : 'input name="digest_username" size="50" value="'+alert,
    pass2_re : "<title>Resin Admin Login"
  );
}
if (!vuln) exit(0, "No vulnerable installs of Resin were discovered on the web server on port "+port+".");
