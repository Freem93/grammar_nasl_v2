#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58528);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 23:56:13 $");

  script_name(english:"Tivoli Provisioning Manager Express for Software Distribution Detection");
  script_summary(english:"Checks for Tivoli Provisioning Manager Express web application");

  script_set_attribute(attribute:"synopsis", value:
"A web-based software distribution application was detected on the
remote host.");
  script_set_attribute(attribute:"description", value:
"Tivoli Provisioning Manager Express for Software Distribution, an
application for managing software distribution, was detected on the
remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cc2adbe");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_provisioning_manager_express");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

# Make sure the banner looks correct unless we're paranoid.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port, exit_on_fail:TRUE);
  if ('WebSphere Application Server' >!< banner)  exit(0, 'The web server on port '+port+' isn\'t WebSphere Application Server.');
}

# Tivoli Provisioning Manager Express for Software Distribution
# will probably always be in the /tpmx directory
login_page = '/tpmx/logon.do';
res = http_send_recv3(method:"GET", item:login_page, port:port, exit_on_fail:TRUE);

if ('<title>Tivoli Provisioning Manager Express for Software Distribution' >< res[2])
{
  # If detection succeeded, try to get the version number as well
  pattern = 'var js_about_version=\'([0-9\\.]+([^\']+\'|\'))';
  ver = NULL;
  match = eregmatch(string:res[2], pattern:pattern);
  if (match)
  {
    ver = match[1];
  }
  if (ver) ver = ver - '\'';

  install = add_install(dir:'/tpmx/', ver:ver, appname:'tivoli_provisioning_manager_exp_for_software_dist', port:port);

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'Tivoli Provisioning Manager Express for Software Distribution',
      installs:install,
      item:'logon.do',
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, 'Tivoli Provisioning Manager Express for Software Distribution wasn\'t detected on port '+port+'.');
