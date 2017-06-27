#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52053);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_name(english:"MySQL Eventum Detection");
  script_summary(english:"Looks for MySQL Eventum");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is running an open source issue tracking system
written in PHP."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running MySQL Eventum, an open source web-based issue tracking
system written in PHP."
  );
  script_set_attribute(attribute:"see_also", value:"http://forge.mysql.com/wiki/Eventum/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:eventum");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

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
app_pat1 = '<form name=\\"login_form\\" onSubmit=\\".*return checkFormSubmission\\(this, \'validateForm\'\\);\\" method=\\"post\\" action=\\"login\\.php\\"';

app_id_str1 = '<input type="hidden" name="cat" value="login">';
app_id_str2 = '<input type="hidden" name="url" value=';
app_id_str3 = "<b>* Requires support for cookies and javascript in your browser</b>";
app_id_str4 = "<h3>Eventum - Login</h3>";
app_id_str5 = "<title>Login - Eventum</title>";

dirs = cgi_dirs();
if (thorough_tests)
{
  dirs = make_list(dirs, '/eventum', '/tracker', '/issues', '/eventum/htdocs', '/tracker/htdocs', '/issues/htdocs');
  dirs = list_uniq(dirs);
}

foreach dir (dirs)
{
  res = http_send_recv3(method:"GET", item:dir+'/', port:port, exit_on_fail:TRUE);

  if (
    (
      app_id_str4 >< res[2] &&
      app_id_str5 >< res[2] &&
      (egrep(pattern:app_pat1, string:res[2]))
    )
    ||
    (
      app_id_str1 >< res[2] &&
      app_id_str2 >< res[2] &&
      app_id_str3 >< res[2] &&
      (egrep(pattern:app_pat1, string:res[2]))
    )
  )
  {
    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'eventum',
      ver      : NULL,
      port     : port
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, "MySQL Eventum wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Eventum',
    installs     : installs,
    port         : port
  );
  security_note(port: port, extra: report);
}
else security_note(port);
