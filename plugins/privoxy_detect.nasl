#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65947);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/29 20:44:45 $");

  script_name(english:"Privoxy Detection");
  script_summary(english:"Looks for Privoxy.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web proxy.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Privoxy, a non-caching web proxy.");
  script_set_attribute(attribute:"see_also", value:"http://www.privoxy.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:privoxy:privoxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8118);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8118);
app_name = "Privoxy";

banner = get_http_banner(port:port, exit_on_fail:TRUE);
pat = "Privoxy ([0-9.]+)";

if ("Proxy-Agent: Privoxy" >!< banner) audit(AUDIT_NOT_LISTEN, app_name, port);

# Grab version from banner
version = UNKNOWN_VER;
matches = eregmatch(pattern:pat, string:banner);
if (matches) version = matches[1];

installs = add_install(
  installs : installs,
  ver      : version,
  dir      : '',
  appname  : app_name,
  port     : port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app_name,
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
