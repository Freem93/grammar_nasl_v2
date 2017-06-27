#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65669);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_name(english:"Foscam Detection");
  script_summary(english:"Looks for a Foscam IP Camera");

  script_set_attribute(attribute:"synopsis", value:"The remote host is an IP Camera.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Foscam IP Camera with an embedded web server.

Note that Foscam cameras can be re-branded and re-sold by other
vendors.");
  script_set_attribute(attribute:"see_also", value:"http://www.foscam.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:foscam:ip_camera_firmware");

  script_set_attribute(attribute:"plugin_type", value:"remote");
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

port = get_http_port(default:80);

appname = "Foscam";

url = "/";
initialPage = http_get_cache(item:url, port:port, exit_on_fail:TRUE);
if ('meta http-equiv="Content-Type' >!< initialPage) audit(AUDIT_NOT_DETECT, appname, port);

url = "/get_status.cgi";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (
  egrep(string:res[2], pattern:"sys_ver=") &&
  "p2p_local_port=" >< res[2] &&
  "app_ver=" >< res[2]
)
{
  match = eregmatch(string:res[2], pattern:"sys_ver=\'([0-9.]+)\'");
  if (isnull(match)) ver = UNKNOWN_VER;
  else ver = match[1];

  installs = add_install(
    port     : port,
    dir      : "/",
    ver      : ver,
    appname  : "foscam"
  );

  set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name : appname,
      installs     : installs,
      port         : port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_NOT_DETECT, appname, port);
