#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69176);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_name(english:"PineApp Mail-SeCure Detection");
  script_summary(english:"Looks for PineApp Mail-SeCure");

  script_set_attribute(
    attribute:"synopsis",
    value:"An email security application is running on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"PineApp Mail-SeCure, a perimeter-based email security application with
a web-based interface, is running on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www2.pineapp.com/products/1/email-security");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pineapp:mail-secure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 7080, 7443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:7080);
app = "PineApp Mail-SeCure";

if (thorough_tests) dirs = list_uniq(make_list("/mailsecure", "/mail-secure", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();

regexes = make_list();
regexes[0] = make_list(
  'href="http://www.pineapp.com" target="_blank"\\>PineApp',
  '\\<title\\>PineApp'
);
checks["/admin/index.html"] = regexes;

installs = find_install(
  appname : "pineapp_mailsecure",
  checks  : checks,
  dirs    : dirs,
  port    : port
);

if (isnull(installs))  audit(AUDIT_WEB_APP_NOT_INST, app, port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app,
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
