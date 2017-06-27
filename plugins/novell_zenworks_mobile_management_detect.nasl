#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65550);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_name(english:"Novell ZENworks Mobile Management Detection");
  script_summary(english:"Detects Novell ZENworks Mobile Management login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web-based mobile device management
system."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Novell ZENworks Mobile Management, a web-
based system for managing mobile devices on enterprise networks."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/products/zenworks/mobile-management/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_mobile_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Novell ZENworks Mobile Management";

port = get_http_port(default:80, embedded:FALSE);

res = http_send_recv3(item:"/",
                      port:port,
                      method:"GET",
                      exit_on_fail:TRUE);

installs = NULL;

if ("<title>ZENworks Mobile Management" >< res[2] && "loginForm" >< res[2])
{
  version = UNKNOWN_VER;

  # <p id="version">Version 2.6.0</p>
  item = eregmatch(pattern:'<p id="version">([^<]+)',
                   string: res[2]);

  # text portion of string is dependent on language selected,
  # ignore that and extract numerical version info
  if (!isnull(item))
  {
    item = eregmatch(pattern:'([0-9.]+)', string:item[1]);
    if (!isnull(item)) version = item[1];
  }

  installs = add_install(
    installs:installs,
    dir:'/',
    appname:'novell_zenworks_mobile_management',
    port:port,
    ver:version
  );
}

if (!isnull(installs))
{
  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:appname,
      installs:installs,
      port:port
    );
    security_note(extra:report, port:port);
  }
  else security_note(port);
}
else audit(AUDIT_WEB_APP_NOT_INST, appname, port);
