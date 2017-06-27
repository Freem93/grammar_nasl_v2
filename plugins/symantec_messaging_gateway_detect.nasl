#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62009);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/05 18:54:42 $");

  script_name(english:"Symantec Messaging Gateway Detection");
  script_summary(english:"Detects the SMG login page.");

  script_set_attribute(attribute:"synopsis", value:
"A messaging security application was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"Symantec Messaging Gateway (formerly known as Symantec Brightmail
Gateway) was detected on the remote host. This application provides
inbound and outbound messaging security.");
  script_set_attribute(attribute:"see_also", value:"https://www.symantec.com/products/threat-protection/messaging-gateway");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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
dir = '/brightmail';
page = '/viewLogin.do';
res = http_send_recv3(method:'GET', item:dir + page, port:port, exit_on_fail:TRUE);
if (
  res[2] !~ '<title>\\s*?Symantec Messaging Gateway[^<]+Login\\s*?</title>' &&
  res[2] !~ '<title>Symantec Brightmail[^ <]* Gateway[^<]+Login</title>'
)
{
  audit(AUDIT_WEB_FILES_NOT, 'Symantec Messaging Gateway', port);
}

match = eregmatch(string:res[2], pattern:'>\\s*?Version ([0-9.]+)\\s*?<');
if (isnull(match))
  ver = NULL;
else
  ver = match[1];

install = add_install(appname:'sym_msg_gateway', ver:ver, dir:dir, port:port);

if (report_verbosity > 0)
{
  report = get_install_report(display_name:'Symantec Messaging Gateway', installs:install, item:page, port:port);
  security_note(port:port, extra:report);
}
else security_note(port);
