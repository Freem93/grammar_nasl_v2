#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42964);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");

  script_cve_id("CVE-2009-3303");
  script_bugtraq_id(37088);
  script_osvdb_id(60485);
  script_xref(name:"Secunia", value:"37450");

  script_name(english:"GForge help/tracker.php helpname Parameter XSS");
  script_summary(english:"Tries to inject script code through 'helpname' parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is prone to a cross-
site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of GForge fails to sanitize user-supplied input
to the 'helpname' parameter in the 'help/tracker.php' script before
using it to generate dynamic HTML content.

An unauthenticated, remote attacker may be able to leverage this issue
to inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2009/dsa-1937");
  script_set_attribute(attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2009/Nov/237");
  script_set_attribute(
    attribute:"solution",
    value:
"If using GForge on Debian, refer to Debian Security Advisory for patches.
Otherwise, contact the vendor for a solution."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gforge:gforge");

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("gforge_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/gforge");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");

install = get_install_from_kb(appname:'gforge', port:port);
if (isnull(install)) exit(0, "The 'www/"+port+"/gforge' KB item is missing.");

dir = install['dir'];

# Try to exploit the issue.
exploit = '<script>alert(' + "'" + SCRIPT_NAME + "'" + ')</script>';

vuln = test_cgi_xss(
  port     : port,
  cgi      : "/help/tracker.php",
  dirs     : make_list(dir),
  qs       : "helpname="+exploit,
  pass_str : 'UNKNOWN HELP REQUEST:'+exploit,
  pass2_re : "<(title|TITLE)>Tracker Help - <script>alert"
);

if (!vuln)
{
  install_url = build_url(qs:install['dir'] + '/', port:port);
  exit(0, "The GForge install at " + install_url + " is not affected.");
}
