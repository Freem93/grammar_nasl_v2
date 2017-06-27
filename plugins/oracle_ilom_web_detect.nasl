#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61645);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_name(english:"Oracle Integrated Lights Out Manager Web Detection");
  script_summary(english:"Looks for ILOM web interface");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An out-of-band management application was detected on the remote web
server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web interface for Oracle Integrated Lights Out Manager (ILOM) was
detected on the remote host.  ILOM is used to perform out-of-band
management on Oracle Sun servers."
  );
  script_set_attribute(attribute:"see_also", value:"http://docs.oracle.com/cd/E19860-01/E21549/z400000c1393879.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:embedded_lights_out_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:integrated_lights_out_manager_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, embedded:TRUE);

if (report_paranoia < 2)
{
  # Server: Sun-ILOM-Web-Server/1.0
  # Server: Oracle-ILOM-Web-Server/1.0
  banner = get_http_banner(port:port);

  if (isnull(banner)) audit(AUDIT_NO_BANNER, port);
  if ('ILOM-Web-Server/' >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, 'ILOM');
}

res = http_send_recv3(method:'GET', item:'/home.asp', port:port, exit_on_fail:TRUE);
if ('Integrated Lights Out Manager' >!< res[2]) audit(AUDIT_WEB_APP_NOT_INST, 'ILOM', port);

res = http_send_recv3(method:'GET', item:'/about/frame-content.asp', port:port, exit_on_fail:TRUE);
match = eregmatch(string:res[2], pattern:'Version ([^<]+)</div>');
if (isnull(match)) ver = NULL;
else ver = match[1];

install = add_install(appname:'ilom', port:port, dir:'', ver:ver);

if (report_verbosity > 0)
{
  report = get_install_report(display_name:'Oracle ILOM', port:port, installs:install);
  security_note(port:port, extra:report);
}
else security_note(port);
