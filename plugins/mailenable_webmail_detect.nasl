#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59568);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"MailEnable WebMail Detection");
  script_summary(english:"Checks for MailEnable WebMail");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server hosts a web-based email application."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts the webmail component of MailEnable, a
mail server application."
  );
  script_set_attribute(attribute:"see_also", value:"http://mailenable.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/iis");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port, exit_on_fail:TRUE);
if ("IIS/" >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, "IIS");

# Loop through directories. Directory names obtained from
# http://www.mailenable.com/kb/content/view.asp?ID=ME020029
if (thorough_tests) dirs = list_uniq(make_list("/mewebmail", "/hoodoo", "/mondo", "/base", "/default", "/enterprise", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();

foreach dir (dirs)
{
  url = strcat(dir, '/');
  res = http_send_recv3(method:"GET", item:url, port:port, follow_redirect:5, exit_on_fail:TRUE);

  if (
    '<title>MailEnable Web Mail' >< res[2] ||
    '<title>MailEnable - Webmail' >< res[2]
  )
  {
    get_url = http_last_sent_request();
    get_split = egrep(pattern:'GET', string:get_url);
    loc = split(get_split, sep:" ", keep:FALSE);

    version = UNKNOWN_VER;

    # Save info about the install.
    installs = add_install(
      appname  : "mailenable_webmail",
      installs : installs,
      port     : port,
      dir      : loc[1],
      ver      : version
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (max_index(keys(installs)) == 0) audit(AUDIT_NOT_INST, "MailEnable WebMail");

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : '',
    display_name : "MailEnable WebMail"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
