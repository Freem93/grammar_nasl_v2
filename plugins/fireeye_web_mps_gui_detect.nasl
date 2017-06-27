#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70295);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/01/29 20:37:27 $");

  script_name(english:"FireEye Web MPS GUI Detection");
  script_summary(english:"Looks for evidence of FireEye Web MPS GUI");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is the admin console for a security product."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is the FireEye Web Malware Protection System
(MPS) GUI, which provides a web-based configuration interface for a
FireEye Web MPS appliance."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.fireeye.com/products-and-solutions/web-security.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fireeye:web_mps_gui");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:443);

app = "FireEye Web MPS GUI";

dirs = make_list("/");

regexes = make_list();
regexes[0] = make_list(
  "<title>FireEye( NX 10000| Enterprise|) - Please Log In",
  '<strong title="Web Malware Protection System">',
  'Copyright [0-9]+ FireEye, Inc\\. All rights reserved\\.'
);

checks = make_array();
checks["/login/login"] = regexes;

installs = find_install(
  appname : "fireeye_mps",
  checks  : checks,
  dirs    : dirs,
  port    : port
);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, app, port);

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
