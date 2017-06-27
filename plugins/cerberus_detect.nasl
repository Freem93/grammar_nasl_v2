#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65983);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/16 19:56:51 $");

  script_name(english:"Cerb Detection");
  script_summary(english:"Looks for Cerb");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a web-based business collaboration 
and automation tool."); 
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Cerb, a web-based business collaboration
and automation tool.");
  script_set_attribute(attribute:"see_also", value:"http://www.cerberusweb.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cerberus:cerberus_helpdesk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/cerberus", "/cerb", "/cerb6", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();

regexes = make_list();
regexes[0] = make_list('Cerberus Helpdesk', 'a href="http://www.cerberusweb.com/"', '/index.php/login">sign on</a>');
regexes[1] = make_list("WebGroup Media LLC - Version ([0-9\.]+(-[A-Za-z]+\d)?)");
checks["/index.php/login"] = regexes;

installs = find_install(appname:"cerb", checks:checks, dirs:dirs, port:port);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "Cerb", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Cerb',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
