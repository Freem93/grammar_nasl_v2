#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84549);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2015-2665", "CVE-2015-4342", "CVE-2015-4454");
  script_bugtraq_id(75108, 75270, 75309);
  script_osvdb_id(123118, 123413, 123414);

  script_name(english:"Cacti < 0.8.8d Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Cacti.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cacti application
running on the remote web server is prior to version 0.8.8d. It is,
therefore, potentially affected by multiple vulnerabilities :

  - A stored cross-site scripting vulnerability exists due
    to improper validation of user-supplied input in
    graphs.php. A remote attacker can exploit this to inject
    arbitrary web script or HTML. (CVE-2015-2665)

  - A SQL injection vulnerability exists due to improper
    validation of user-supplied input to the 'cdef'
    parameter in cdef.php. A remote attacker can exploit
    this to execute arbitrary SQL commands. (CVE-2015-4342)

  - A SQL injection vulnerability exists due to improper
    validation of user-supplied input to the
    'graph_template_id' parameter in graph_templates.php. A
    remote attacker can exploit this to execute arbitrary
    SQL commands. (CVE-2015-4454)");
  script_set_attribute(attribute:"see_also", value:"http://www.cacti.net/release_notes_0_8_8d.php");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-VD-15-017/");
  script_set_attribute(attribute:"see_also", value:"http://svn.cacti.net/viewvc?view=rev&revision=7719");
  script_set_attribute(attribute:"see_also", value:"http://bugs.cacti.net/view.php?id=2572");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cacti 0.8.8d or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cacti:cacti");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("cacti_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/cacti", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'cacti';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

install_url = build_url(qs:install['path'], port:port);
version = install['version'];

# Versions < 0.8.8d are affected.
ver = split(version, sep:'.', keep:FALSE);
if (
  int(ver[0]) == 0 &&
  (
   int(ver[1]) < 8 ||
   (int(ver[1]) == 8 && ver[2] =~ '^([0-7][a-z]?|8[abc]?)$')
  )
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =  '\n  URL               : ' + install_url +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 0.8.8d' +
              '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Cacti", install_url, version);
