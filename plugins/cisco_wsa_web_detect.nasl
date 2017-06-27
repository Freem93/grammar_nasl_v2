#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69080);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/09 21:53:13 $");

  script_name(english:"Cisco Web Security Appliance Web Detection");
  script_summary(english:"Looks for the WSA login page.");

  script_set_attribute(attribute:"synopsis", value:
"A web management interface was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The web management interface for a Cisco Web Security Appliance (WSA)
was detected on the remote host.");
  # https://www.cisco.com/c/en/us/products/security/web-security-appliance/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd41b0ab");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8443);
dir = '';
page = '/login?redirects=10';
url = dir + page;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
control = 0;

# Older versions
if ('<title>Cisco IronPort' >< res[2])
  control += 1;

# Newer versions
if (res[2] =~ "<title>\s+Cisco\s+Web Security Virtual Appliance")
  control += 1;

# All versions, apparently
if ('/help/wsa_help/login.html' >< res[2])
  control += 1;
else
  control -= 1;

if (control <= 0)
  audit(AUDIT_WEB_APP_NOT_INST, 'Cisco Web Security Appliance', port);

# Older versions
model = FALSE;
match = eregmatch(string:res[2], pattern:'alt="(Cisco )?IronPort ([^"]+)" class="logo"');
if (!isnull(match))
  model = match[2];

# Newer versions
if (!model)
{
  match = eregmatch(string:res[2], pattern:'text_login_model">(Cisco )?([A-Za-z0-9]+)</p');
  if (!isnull(match))
    model = match[2];
}

if (model)
  set_kb_item(name:'cisco_wsa/' + port + '/model', value:match[2]);


match = eregmatch(string:res[2], pattern:"(v|Version: )([0-9.-]+) for Web");
if (isnull(match))
  ver = NULL;
else
  ver = match[2];

install = add_install(appname:'cisco_wsa', dir:dir, port:port, ver:ver);

if (report_verbosity > 0)
{
  report = get_install_report(display_name:'Cisco Web Security Appliance', installs:install, port:port);
  security_note(port:port, extra:report);
}
else security_note(port);
