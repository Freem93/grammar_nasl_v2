#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65687);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_name(english:"Eye-Fi Helper Detection");
  script_summary(english:"Checks for a Eye-Fi Helper HTTP banner");

  script_set_attribute(attribute:"synopsis", value:
"A utility used to transfer photos from an SD Card to a computer is
listening on the remote host.");
  script_set_attribute( attribute:"description", value:
"The Eye-Fi Helper software, which is used to transfer photos wirelessly
to a computer, is listening on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.eye.fi/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:eye:eye-fi_helper");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 59278);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:59278);

server = http_server_header(port:port);

match = eregmatch(string:server, pattern:"Eye-Fi Agent/([0-9\.]+)\s*\(.*\)");
if (isnull(match)) audit(AUDIT_WEB_APP_NOT_INST, "Eye-Fi Helper", port);

version = match[1];
installs = add_install(
  dir      : "/",
  appname  : "eyefi_helper",
  ver      : version,
  port     : port
);

if (report_verbosity > 0)
{
  report =
    '\n  URL            : ' + build_url(port:port, qs:"/") +
    '\n  Version source : ' + server +
    '\n  Version        : ' + version + 
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
