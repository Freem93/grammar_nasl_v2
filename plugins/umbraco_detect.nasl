#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61516);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_name(english:"Umbraco Detection");
  script_summary(english:"Looks for Umbraco");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a content management system written in
ASP.NET.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Umbraco, a web-based content management
system written in ASP.NET.");
  script_set_attribute(attribute:"see_also", value:"http://www.umbraco.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:umbraco:umbraco_cms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

if (thorough_tests) dirs = list_uniq(make_list("/umbraco", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();

# Umbraco 5
tag1 = '<meta name="umbraco-page-type" content="umbraco-login-page" />';
# Umbraco 4
tag2 = 'Umbraco - login';
tag3 = '&copy; [0-9 -]+ <a href="http://umbraco.org"';
# Umbraco versions 2 and 3
tag4 = '/umbraco_client/scrollingmenu/style.css';
tag5 = '<title>login</title>';
tag6 = '/umbracoGui.css" type="text/css" rel="stylesheet"';

foreach dir (dirs)
{
  url = dir + '/login.aspx';
  res = http_send_recv3(
    method          : "GET",
    item            : url,
    port            : port,
    exit_on_fail    : TRUE,
    follow_redirect : 1
  );

  # Umbraco 5
  if (res[0] =~ '^HTTP/1\\.[01] +404 ')
  {
     res = http_send_recv3(
       method          : "GET",
       item            : dir + '/Default/',
       port            : port,
       exit_on_fail    : TRUE,
       follow_redirect : 1
    );
  }
  match_tag3 = eregmatch(string:res[2], pattern:tag3);

  if (
       tag1 >< res[2] ||
       (tag2  >< res[2] && match_tag3) ||
       (tag4 >< res[2] && tag5 >< res[2] && tag6 >< res[2])
     )
  {
    version = UNKNOWN_VER;

    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'umbraco',
      ver      : version,
      port     : port
    );
    if (!thorough_tests) break;
  }
}
if (max_index(keys(installs)) == 0) audit(AUDIT_NOT_INST, "Umbraco");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Umbraco',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
