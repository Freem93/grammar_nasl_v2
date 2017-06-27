#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49774);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_name(english:"Nagios XI / Fusion Detection");
  script_summary(english:"Looks for the Nagios XI or Nagios Fusion login page");

  script_set_attribute(attribute:"synopsis", value:"A monitoring service is running on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"The web interface for Nagios XI and / or Nagios Fusion was detected
on the remote host.  These applications are used for enterprise
monitoring and alerting."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nagios.com/products/nagiosxi");
  script_set_attribute(
    attribute:"see_also",
    value:"http://nagios.com/products/nagiosfusion"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);
xi_installs = NULL;
fusion_installs = NULL;


# these dirs are, AFAICT, not configurable
dirs = make_list('/nagiosxi', '/nagiosfusion', cgi_dirs());
dirs = list_uniq(dirs);

prod_pattern = '<input type="hidden" name="product" value="(nagiosxi|nagiosfusion)">';
ver_pattern = '<input type="hidden" name="version" value="([^"]+)">';
build_pattern = '<input type="hidden" name="build" value="([0-9]+)">';

foreach dir (dirs)
{
  ver = NULL;
  prod = NULL;
  url = dir+'/login.php';
  res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

  match = eregmatch(string:res[2], pattern:prod_pattern);
  if (!match) continue;
  prod = match[1];

  match = eregmatch(string:res[2], pattern:ver_pattern, icase:TRUE);
  if (match) ver = match[1];
  match = eregmatch(string:res[2], pattern:build_pattern, icase:TRUE);
  if (match)
  {
    if (isnull(ver)) ver = UNKNOWN_VER;
    ver += ' build ' + match[1];
  }

  if (prod == 'nagiosxi')
  {
    xi_installs = add_install(
      installs:xi_installs,
      dir:dir,
      ver:ver,
      appname:'nagios_xi',
      port:port
    );
  }
  else if (prod == 'nagiosfusion')
  {
    fusion_installs = add_install(
      installs:fusion_installs,
      dir:dir,
      ver:ver,
      appname:'nagios_fusion',
      port:port
    );
  }
}

if (isnull(xi_installs) && isnull(fusion_installs))
  exit(0, 'Nagios XI / Fusion weren\'t detected on port '+port+'.');

if (report_verbosity > 0)
{
  report = '';

  if (!isnull(xi_installs))
  {
    report += get_install_report(
      display_name:'Nagios XI',
      installs:xi_installs,
      port:port
    );
  }
  if (!isnull(fusion_installs))
  {
    report += get_install_report(
      display_name:'Nagios Fusion',
      installs:fusion_installs,
      port:port
    );
  }
  security_note(port:port, extra:report);
}
else security_note(port);

