#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48202);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:24 $");

  script_name(english:"phpwcms Detection");
  script_summary(english:"Looks for phpwcms");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a content management system written in
PHP."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts phpwcms, a web-based content management
system written in PHP."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.phpwcms.de/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpwcms:phpwcms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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

port = get_http_port(default:80, php:TRUE);

installs = NULL;
dirs = cgi_dirs();

if (thorough_tests)
{
  dirs = make_list(dirs, '/phpwcms', '/cms');
  dirs = list_uniq(dirs);
}

foreach dir (dirs)
{
  url = dir + '/index.php';
  res = http_get_cache(
    item         : url,
    port         : port,
    exit_on_fail : TRUE
  );
  if (
      (
      # Newer versions
      'phpwcms | free open source content management system' >< res &&
      'created by Oliver Georgi (oliver at phpwcms dot de) and licensed under GNU/GPL.' >< res &&
      'phpwcms is copyright' >< res
      )
      ||
      (
      # Older versions
      'phpwcms | open source web content management system' >< res &&
      'developed by Oliver Georgi (info@phpwcms.de)' >< res &&
      'visit project page: http://www.phpwcms.de' >< res
      )
  )
  {
    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'phpwcms',
      port     : port
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, "phpwcms wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'phpwcms',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
