#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69074);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/26 15:40:06 $");

  script_name(english:"Cisco Email Security Appliance Web Detection");
  script_summary(english:"Looks for the ESA login page");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web management interface was detected on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web management interface for Cisco Email Security Appliance was
detected on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps10154/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
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
dir = '';
page = '/login?redirects=10';
url = dir + page;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (res[2] !~ "<title>\s*Cisco\s*Email Security (Virtual )?Appliance")
  audit(AUDIT_WEB_APP_NOT_INST, 'Cisco Email Security Appliance', port);

match = eregmatch(string:res[2], pattern:'<p class="text_login_model">Cisco ([^<]+)</p>');
if (!isnull(match))
  set_kb_item(name:'cisco_esa/' + port + '/model', value:match[1]);

match = eregmatch(string:res[2], pattern:"Version: ([0-9.-]+)<");
if (isnull(match))
  ver = NULL;
else
  ver = match[1];

install = add_install(appname:'cisco_esa', dir:dir, port:port, ver:ver);

if (report_verbosity > 0)
{
  report = get_install_report(display_name:'Cisco Email Security Appliance', installs:install, port:port);
  security_note(port:port, extra:report);
}
else security_note(port);

