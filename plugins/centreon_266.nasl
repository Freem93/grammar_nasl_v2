#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87054);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/08 18:22:10 $");

  script_name(english:"Centreon 2.6.6 Multiple XSRF Vulnerabilities");
  script_summary(english:"Checks the version of Centreon.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Centreon application hosted on
the remote web server is version 2.6.x prior to 2.6.6. It is,
therefore affected by multiple undisclosed cross-site request forgery
(XSRF) vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/centreon/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Centreon version 2.6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centreon:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("centreon_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Centreon", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Centreon";
get_install_count(app_name:app, exit_if_zero:TRUE);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);
install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if(version =~ "^2\.6\." && ver_compare(ver:version, fix:"2.6.6", strict:FALSE) < 0)
{
  set_kb_item(name: 'www/' + port + '/XSRF', value: TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 2.6.6\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
