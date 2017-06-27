#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60138);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/07/27 15:05:02 $");

  script_name(english:"Cisco TelePresence Multipoint Switch Web Detection");
  script_summary(english:"Looks for CTMS login page");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web management application is being hosted on the remote web server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is operating as a Cisco TelePresence Multipoint Switch
(CTMS), a network infrastructure component used in videoconferencing. 
The web management application for CTMS was detected on this host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps7315/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_multipoint_switch_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

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

port = get_http_port(default:443);
res = http_get_cache(item:'/', port:port, exit_on_fail:TRUE);
if (
  ('Cisco TelePresence Multipoint Switch</title>' >!< res ||
  '<div class="cuesLoginProductName">Cisco TelePresence Multipoint Switch</div>' >!< res) &&
  'Cisco TelePresence Multipoint Switch Administration</title>' >!< res
)
{
  audit(AUDIT_WEB_FILES_NOT, 'CTMS', port);
}

# the version number is only available w/o auth on older versions
res = http_send_recv3(method:'GET', item:'/aboutBox.do', port:port);
match = eregmatch(string:res[2], pattern:'<div class="cuesAboutVersionInfo">([0-9().]+)</div>');

if (isnull(match))
{
  match = eregmatch(string:res[2], pattern:'Build: ([0-9().]+)</span>');
  ver = NULL;
}

if (match)
  ver = match[1];
else
  ver = NULL;

install = add_install(appname:'cisco_tms', port:port, dir:'', ver:ver);

if (report_verbosity > 0)
{
  report = get_install_report(display_name:'Cisco TelePresence Multipoint Switch', installs:install, port:port);
  security_note(port:port, extra:report);
}
else security_note(port);
