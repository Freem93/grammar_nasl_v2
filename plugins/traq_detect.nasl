#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62891);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/11/12 20:07:12 $");

  script_name(english:"Traq Detection");
  script_summary(english:"Looks for Traq");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a project manager written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Traq, a PHP-powered project manager used
for tracking issues for multiple projects and milestones.");
  script_set_attribute(attribute:"see_also", value:"http://www.traq.io");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:traq:traq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

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

if (thorough_tests) dirs = list_uniq(make_list("/traq", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();

regexes = make_list();
regexes[0] = make_list('Powered by Traq', '&copy; [0-9]+-[0-9]+ (Jack Polgar|TraqProject.org)');
regexes[1] = make_list('Powered by Traq (.+)<br');
checks["/index.php"] = regexes;
checks["/admincp/login.php"] = regexes;

installs = find_install(appname:"traq", checks:checks, dirs:dirs, port:port);
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "Traq", port);

report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Traq',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
