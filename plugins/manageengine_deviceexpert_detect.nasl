#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58426);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/04 18:03:31 $");

  script_name(english:"ManageEngine DeviceExpert Detection");
  script_summary(english:"Looks for evidence of ManageEngine DeviceExpert");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a network device configuration management
application."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts ManageEngine DeviceExpert, a web-
based, multi-vendor change and configuration management application
for network devices written in Java."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.manageengine.com/products/device-expert/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:manageengine:device_expert");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 6060);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:6060);


installs = NULL;
url = '/NCMContainer.cc';

res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE, follow_redirect:1);
if (
 "<title>ManageEngine DeviceExpert</title>" >< res[2] &&
 "de_login_logo.gif" >< res[2]
)
{
  version = UNKNOWN_VER;

  # Save info about the install.
  installs = add_install(
    appname  : "manageengine_deviceexpert",
    installs : installs,
    port     : port,
    dir      : "",
    ver      : version
  );

}
if (isnull(installs))
  exit(0, "ManageEngine DeviceExpert was not detected on the web server on port "+port+".");

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : url,
    display_name : "ManageEngine DeviceExpert"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
