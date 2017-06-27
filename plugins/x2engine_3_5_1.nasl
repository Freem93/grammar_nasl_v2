#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81513);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/26 14:38:27 $");

  script_cve_id("CVE-2013-5692", "CVE-2013-5693");
  script_bugtraq_id(62633, 62634);
  script_osvdb_id(97365, 97366);
  script_xref(name:"EDB-ID", value:"28557");

  script_name(english:"X2Engine < 3.5.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of X2Engine.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the X2Engine application installed on
the remote web server is prior to version 3.5.1. It is, therefore,
potentially affected by multiple vulnerabilities :

  - A PHP file inclusion vulnerability exists due to
    insufficient sanitization of the 'file' HTTP GET
    parameter of the '/index.php/admin/translationManager'
    script. (CVE-2013-5692)

  - A cross-site scripting (XSS) vulnerability exists due to
    insufficient sanitization of the 'model' HTTP GET
    parameter of the 'index.php/admin/editor' script.
    (CVE-2013-5693)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.com/advisory/HTB23172");
  script_set_attribute(attribute:"see_also", value:"http://x2community.com/topic/1005-x2crm-35-released/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/X2Engine/X2Engine/blob/master/CHANGELOG.md");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:x2engine:x2crm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("x2engine_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/X2Engine", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "X2Engine";
fix = "3.5.1";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir + "/login");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 3) ||
  (ver[0] == 3 && ver[1] < 5) ||
  (ver[0] == 3 && ver[1] == 5 && ver[2] < 1)
)
{
  set_kb_item(name:"www/" + port + "/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix+
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
