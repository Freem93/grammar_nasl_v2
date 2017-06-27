#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66326);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/06 13:51:55 $");

  script_name(english:"Lexmark Markvision Enterprise Detection");
  script_summary(english:"Detect Lexmark Markvision Enterprise");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has web-based printer and multi-function device
management software installed."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Lexmark Markvision Enterprise, a web-based printer and multi-function
device management system, was detected on the remote host."
  );
  # http://www1.lexmark.com/en_US/solutions/software-services/device-management/index.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c33d328e");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lexmark:markvision");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports(9788, "Services/www");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Lexmark Markvision Enterprise";

port =  get_http_port(default:9788);

installs = NULL;

version = UNKNOWN_VER;

url = '/mve/help/en/inventory/am_about.html';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>About Information</title>' >!< res[2] ||
  'MarkVision' >!< res[2]
) audit(AUDIT_NOT_DETECT, appname, port);

item = eregmatch(pattern:'<p>MarkVision[ A-Za-z]+([0-9.]+)</p>',string:res[2]);
if (!isnull(item)) version = item[1];

build = "";
item = eregmatch(pattern:'<p>Build[ ]*([^ <]+)</p>', string:res[2]);
if (!isnull(item))
{
  build = item[1];
  set_kb_item(name:'www/'+port+'/lexmark_markvision_enterprise/Build', value:build);
}

installs = add_install(
  appname  : "lexmark_markvision_enterprise",
  installs : installs,
  port     : port,
  dir      : '/mve',
  ver      : version
);

if (report_verbosity > 0)
{
  report = '\n  URL     : ' + build_url(qs:'/mve', port:port) +
           '\n  Version : ' + version;
  if (build != "")
    report += '\n  Build   : ' + build;
  report += '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
