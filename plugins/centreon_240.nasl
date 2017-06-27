#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80223);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/08 18:22:10 $");

  script_cve_id("CVE-2012-5967");
  script_bugtraq_id(56911);
  script_osvdb_id(88430);
  script_xref(name:"EDB-ID", value:"23362");
  script_xref(name:"CERT", value:"856892");

  script_name(english:"Centreon 2.3.3 < 2.4.0 menuXML.php 'menu' Parameter SQL Injection");
  script_summary(english:"Checks the version of Centreon.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Centreon application hosted on
the remote web server is affected by a SQL injection vulnerability in
the 'menu' parameter of the 'menuXML.php' script. A remote,
authenticated user could potentially exploit this issue to execute
arbitrary SQL statements against the back-end database, leading to the
execution of arbitrary code, manipulation of data, or the disclosure
of arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/centreon/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Centreon 2.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centreon:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Versions 2.3.3 < 2.4.0 are affected.
# Second match used to flag 2.4.0 dev versions, as 2.4.0 is the stable version
# which is reported to be fixed
if (
  (version =~ '^2\\.3\\.([3-9])($|[^0-9])') ||
  (version =~ '^2\\.4\\.0([^0-9])')
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 2.4.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
