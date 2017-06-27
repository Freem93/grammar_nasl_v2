#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42800);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_name(english:"HP Power Manager Detection");
  script_summary(english:"Looks for evidence of HP Power Manager");

  script_set_attribute(attribute:"synopsis", value:"A web-based management interface was detected on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"HP Power Manager, a web interface for managing an HP uninterruptible
power supply (UPS), was detected on the remote web server."
  );
  # http://h18004.www1.hp.com/products/servers/proliantstorage/power-protection/software/power-manager/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bcb7c65");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:power_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
# This is incompatible with the paranoid branch
# script_require_keys("www/goahead");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, embedded:TRUE);

# Make sure the banner looks correct unless we're paranoid.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (isnull(banner))
    exit(1, "Unable to get web server banner on port "+port+".");
  if ('GoAhead-Webs' >!< banner)
    exit(0, "The web server on port "+port+" isn't GoAhead-Webs.");
}

# Power Manager runs in a self contained web server, and will probably always
# be in the root directory.
login_page = '/index.asp';
res = http_get_cache(item:login_page, port:port, exit_on_fail: 1);

if ('<title>HP Power Manager</title>' >< res)
{
  # If detection succeeded, try to get the version number as well
  pattern = 'HP Power Manager ([0-9.]+) (\\(Build ([0-9]+)\\))?';
  ver_page = '/CPage/About_English.asp';
  res = http_send_recv3(method:"GET", item:ver_page, port:port, exit_on_fail: 1);

  ver = NULL;
  match = eregmatch(string:res[2], pattern:pattern);
  if (match)
  {
    ver = match[1];
    if (match[3]) ver += '.' + match[3];
  }

  install = add_install(dir:'/', ver:ver, appname:'hp_power_mgr', port:port);

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:"HP Power Manager",
      installs:install,
      item:login_page,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "HP Power Manager wasn't detected on port " + port + ".");
