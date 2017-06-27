#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69950);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/18 17:46:11 $");

  script_name(english:"Management Center for Cisco Security Agents Detection");
  script_summary(english:"Checks for Management Center for Cisco Security Agents");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web management interface was detected on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Management Center for Cisco Security Agents was detected on the
remote host.  This management interface is used by Cisco Security Agent,
an endpoint security application."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/sw/secursw/ps5057/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:443);
appname = 'Management Center for Cisco Security Agents';

dir = '';

res = http_send_recv3(
  method  : "GET",
  port    : port,
  item    : dir + "/csamc52/webadmin?page=invalid&type=browser",
  exit_on_fail : TRUE
);

if (
  ">Management Center for Cisco Security Agents" >!< res[2] &&
  "img/brws_detect.js" >!< res[2]
) audit(AUDIT_WEB_APP_NOT_INST, appname, port);


# Get version
version = UNKNOWN_VER;

ver = eregmatch(
  pattern : "\>Management Center for Cisco Security Agents V([0-9.]+) \</font",
  string  : res[2]
);
if (!isnull(ver)) version = ver[1];

install = add_install(
  appname : 'cisco_security_agent',
  dir     : dir,
  ver     : version,
  port    : port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : appname,
    installs     : install,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
