#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69854);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/12 17:23:51 $");

  script_name(english:"Cisco Video Surveillance Manager Web Detection");
  script_summary(english:"Looks for the vsmc.html page");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web management interface was detected on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web management interface for Cisco Video Surveillance Management
Console was detected on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps10818/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:video_surveillance_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
app = 'Cisco Video Surveillance Management Console';

dir = '';

res = http_send_recv3(
  method : "GET",
  item   : dir + "/vsmc.html",
  port   : port,
  exit_on_fail : TRUE
);

if (
  "<title>Video Surveillance Management Console" >!< res[2] &&
  'src="inc/packages.php"' >!< res[2]
) audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Try and grab the VSMS version
version = UNKNOWN_VER;

res2 = http_send_recv3(
  method : "GET",
  item   : dir + "/inc/packages.php",
  port   : port,
  exit_on_fail : TRUE
);

if ("<title>Configuration Overview" >< res2[2])
{
  ver = eregmatch(pattern:"Cisco_VSMS-(.*)", string:res2[2]);
  if (!isnull(ver)) version = ver[1];
}

install = add_install(
  appname : 'cisco_vsm',
  dir     : dir,
  port    : port,
  ver     : version
);

if (report_verbosity > 0)
{
  report = get_install_report(display_name:app, installs:install, port:port);
  security_note(port:port, extra:report);
}
else security_note(port);

