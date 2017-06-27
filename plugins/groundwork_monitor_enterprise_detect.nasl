#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67017);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/28 13:20:14 $");

  script_name(english:"GroundWork Monitor Enterprise Detection");
  script_summary(english:"Detects GroundWork Monitor Enterprise");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has web-based network application and cloud monitoring
software installed."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of GroundWork Monitor Enterprise
installed.  GroundWork Monitor Enterprise is a network application and
cloud monitoring application."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.gwos.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:gwos:groundwork_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports(80, "Services/www");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "GroundWork Monitor Enterprise";

port =  get_http_port(default:80);

installs = NULL;

version = UNKNOWN_VER;

url = '/portal';
res = http_send_recv3(method:"GET",
                      item:url,
                      port:port,
                      # at least 15 redirects before page will load
                      follow_redirect:20,
                      exit_on_fail:TRUE);
if (
  '<title>GroundWork Enterprise Edition' >!< res[2] ||
  'usernamePasswordLoginForm' >!< res[2]
) audit(AUDIT_NOT_DETECT, appname, port);

item = eregmatch(
         pattern:'<title>GroundWork Enterprise Edition[ ]*([0-9.]+)</title>',
         string:res[2]
       );
if (!isnull(item)) version = item[1];

installs = add_install(
  appname  : "groundwork_monitor_enterprise",
  installs : installs,
  port     : port,
  dir      : '/portal',
  ver      : version
);

if (report_verbosity > 0)
{
  report = '\n  URL     : ' + build_url(qs:'/portal', port:port) +
           '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
