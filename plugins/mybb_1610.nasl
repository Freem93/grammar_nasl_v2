#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68995);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_bugtraq_id(59407);
  script_osvdb_id(92686, 92683, 92684, 92685, 92687, 92688, 92689);

  script_name(english:"MyBB < 1.6.10 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MyBB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MyBB install hosted on the remote
web server is affected by multiple vulnerabilities :

  - A SQL injection vulnerability exists due to improper
    sanitization of user-supplied input during database
    optimization. (VulnDB 92683)

  - A SQL injection vulnerability exists due to improper
    sanitization of user-supplied input when creating
    database backups. (VulnDB 92684)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input passed via
    theme names. (VulnDB 92685)

  - An information disclosure vulnerability exists due to
    improper verification of permissions for forums where
    a user can only see their own threads. (VulnDB 92686)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input passed via
    the debug page. (VulnDB 92687)

  - An unspecified vulnerability exists due to improper
    validation of user-supplied input in modcp.php.
    (VulnDB 92688)

  - An unspecified vulnerability exists due to improper
    validation of user-supplied input in calendar.php.
    (VulnDB 92689)

Note that Nessus has not tested for these issues but has instead
relied on the application's self-reported version number.");
  # http://blog.mybb.com/2013/04/22/mybb-1-6-10-released-security-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ccb481c");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.6.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/MyBB", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MyBB";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

version = install['version'];
install_url = build_url(port:port, qs:install['path']);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = "1.6.10";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
