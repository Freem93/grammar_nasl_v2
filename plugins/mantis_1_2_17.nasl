#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80913);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/23 14:22:56 $");

  script_cve_id("CVE-2014-2238");
  script_bugtraq_id(65903);
  script_osvdb_id(103842);

  script_name(english:"MantisBT 1.2.13 - 1.2.16 'admin_config_report.php' SQLi");
  script_summary(english:"Checks the version of Mantis.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MantisBT application hosted on
the remote web server is 1.2.13 or later but prior to 1.2.17. It is,
therefore, affected by an input validation error related to the
'filter_config_id' parameter in the script 'admin_config_report.php',
which could allow SQL injection attacks.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/blog/?p=288");
  # http://www.mantisbt.org/bugs/changelog_page.php?project=mantisbt&version=1.2.17
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6a124b8");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q1/490");
  script_set_attribute(attribute:"see_also", value:"http://mantisbt.domainunion.de/bugs/view.php?id=17055");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
  script_require_keys("installed_sw/MantisBT", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port, exit_if_unknown_ver:TRUE);
install_url = build_url(port:port, qs:install['path']);
version = install['version'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions 1.2.13 < 1.2.17 are vulnerable
if (
  (ver[0] == 1 && ver[1] == 2 && ver[2] >= 13)
  &&
  (ver[0] == 1 && ver[1] == 2 && ver[2] < 17)
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.2.17\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
