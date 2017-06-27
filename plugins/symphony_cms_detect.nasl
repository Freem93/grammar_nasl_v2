#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46818);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Symphony Detection");
  script_summary(english:"Looks for the Symphony admin login page");

  script_set_attribute(attribute:"synopsis",value:
"A content management system is hosted on the remote web server.");
  script_set_attribute(attribute:"description",value:
"Symphony, an XSLT-powered, open source content management system, is
hosted on the remote web server.");
  script_set_attribute(attribute:"see_also",value:"http://www.getsymphony.com/");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date",value:"2010/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symphony-cms:symphony_cms"); 
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www",80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc"); 
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/symphony", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = NULL;
item = "/index.php";

foreach dir (dirs)
{
  # Grab the admin login page.
  url = dir + item;
  res = http_send_recv3(port:port, method:"GET", item:url + "?mode=administration", exit_on_fail:TRUE);
  
  # If it looks like Symphony...
  if (
    res[2] =~ '<title>(Symphony|Login) &ndash; (Symphony|Login)</title>' &&
    '<h1>Symphony</h1>' >< res[2] &&
    '<legend>Login</legend>' >< res[2]
  )
  {
   installs = add_install(
      appname  : "symphony",
      installs : installs,
      port     : port,
      dir      : dir
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, 'Symphony', port);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "Symphony",
    item         : item
  );
  security_note(port:port, extra:report);
}
else security_note(port);
