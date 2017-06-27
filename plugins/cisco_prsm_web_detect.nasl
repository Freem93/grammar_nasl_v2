#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62181);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/04 00:47:26 $");

  script_name(english:"Cisco Prime Security Manager Web Detection");
  script_summary(english:"Looks for Cisco PRSM login page.");

  script_set_attribute(attribute:"synopsis", value:"A web management interface is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The web interface for Cisco Prime Security Manager (PRSM) was detected
on the remote host. PRSM is the management tool used for Cisco ASA CX.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps12635/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'Cisco PRSM';

# PRSM listens on 443 by default
port = get_http_port(default:443);

page = '/authentication/login/';
url = build_url(qs:page, port:port);
res = http_send_recv3(method:'GET', port:port, item:url, exit_on_fail:TRUE);

if ('<title>Cisco Prime Security Manager Login Page</title>' >!< res[2])
  audit(AUDIT_WEB_APP_NOT_INST, app, url);

match = eregmatch(string:res[2], pattern:'productVersion[=:]["\'](Version )?([0-9.]+(?: ?\\([0-9]+\\))?)["\']');
if (isnull(match)) ver = UNKNOWN_VER;
else ver = match[2];

register_install(
  app_name : app,
  version  : ver,
  path     : page,
  port     : port,
  cpe      : "cpe:/a:cisco:prime_security_manager",
  webapp   : TRUE
);

report_installs(app_name:app, port:port);
