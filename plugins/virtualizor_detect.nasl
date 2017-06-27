#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69043);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/11/04 22:14:20 $");

  script_name(english:"Virtualizor Detection");
  script_summary(english:"Looks for Virtualizor");

  script_set_attribute(attribute:"synopsis", value:"A VPS management application is running on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"Virtualizor, a web-based VPS (Virtual Private Server) control panel is
running on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.virtualizor.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:softaculous:virtualizor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 4082, 4083);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:4082);

if (thorough_tests) dirs = list_uniq(make_list("/virtualizor", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();

regexes = make_list();
regexes[0] = make_list(
  "\>Powered By Virtualizor",
  '\\<a href="http://www\\.virtualizor.com'
);
regexes[1] = make_list(
  "\>Powered By Virtualizor ([0-9.]+)\</a\>",
  "\>Powered By Virtualizor\</b\> ([0-9.]+)\</a\>"
);
checks["/index.php"] = regexes;

installs = find_install(
  appname : "virtualizor",
  checks  : checks,
  dirs    : dirs,
  port    : port
);

if (isnull(installs))  audit(AUDIT_WEB_APP_NOT_INST, "Virtualizor", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Virtualizor",
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
