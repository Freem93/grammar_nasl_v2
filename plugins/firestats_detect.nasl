#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47745);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/10/01 01:43:19 $");

  script_name(english:"FireStats Detection");
  script_summary(english:"Checks for FireStats.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an open source web statistics application
written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts FireStats, an open source web statistics
application written in PHP.");

  script_set_attribute(attribute:"see_also", value:"http://firestats.cc/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/16");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:edgewall:firestats");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);
app = 'FireStats';

dirs = cgi_dirs();

if (thorough_tests)
{
  dirs = list_uniq(make_list(dirs, '/firestats'));

  # Since FireStats can be installed standalone of as a plugin in WordPress
  # Check WordPress for evidence of FireStats being installed
  wp = get_install_count(app_name:"WordPress", exit_if_zero:FALSE);
  wp_path = '/wp-content/plugins/firestats';

  if (wp > 0)
  {
    wp_inst = get_installs(
      app_name : "WordPress",
      port     : port,
      exit_if_not_found : FALSE
    );

    foreach inst (wp_inst[1])
      dirs = list_uniq(make_list(dirs, inst['path'] + wp_path));
  }
}

installs = 0;
foreach dir (dirs)
{
  url = dir + '/index.php';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    '<title>FireStats</title>' >< res[2] &&
    'If you have any problems or questions, please visit the <a href=\'http://firestats.cc\'>' >< res[2]
  )
  {
    version = NULL;
    pat  = 'FireStats ([0-9\\.]+)-[^<]+<br/>If you have any problems or questions';
    matches = egrep(pattern:pat, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }
    installs++;
    if (empty_or_null(version)) version = UNKNOWN_VER;

    register_install(
      app_name : app,
      path     : dir,
      version  : version,
      port     : port,
      cpe      : "cpe:/a:edgewall:firestats",
      webapp   : TRUE
    );
  }

  if (!thorough_tests) break;
}

if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(port:port);
