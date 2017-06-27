#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47151);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/22 21:34:17 $");

  script_name(english:"Simple Machines Forum Detection");
  script_summary(english:"Checks for Simple Machines Forum.");

  script_set_attribute(attribute:"synopsis", value:
"An open source forum application is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Simple Machines Forum (SMF), an open source web forum application
written in PHP, is running on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"http://www.simplemachines.org");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:simplemachines:simple_machines_forum");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'Simple Machines Forum';
port = get_http_port(default:80, php:TRUE);

dirs = cgi_dirs();
if (thorough_tests)
{
  dirs = list_uniq(make_list(dirs, '/smf', '/forum', '/forums'));
}

installs = NULL;
foreach dir (dirs)
{
  url = dir + '/index.php';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    'index.php?action=credits" title="Simple Machines Forum" ' >< res[2] ||
    'Powered by <a href="http://www.simplemachines.org/" title="Simple Machines Forum"' >< res[2] ||
    (
      '<a href="http://www.simplemachines.org/about/copyright.php" title="Free Forum Software"' >< res[2] &&
      'Simple Machines LLC' >< res[2]
    )
  )
  {
    version = NULL;
    pat = 'a href="[^"]+" title="Simple Machines Forum"[^>]+>(Powered by )?SMF ([0-9\\.]+( RC[0-9]+)?)';
    matches = egrep(pattern:pat, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          version = item[2];
          break;
        }
      }
    }

    installs = add_install(
      installs:installs,
      ver:version,
      dir:dir,
      appname:'simple_machines_forum',
      port:port
    );

    if (thorough_tests) break;
  }
}

if (isnull(installs)) audit(AUDIT_NOT_DETECT, appname, port);

report = get_install_report(
  display_name:appname,
  installs:installs,
  port:port);

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
