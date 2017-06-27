#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62967);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/11/20 00:56:49 $");

  script_name(english:"Novell Sentinel Log Manager Web Detection");
  script_summary(english:"Looks for SLM login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web interface for a log management system was detected on the
remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web management interface for Novell Sentinel Log Manager (formerly
known as NetIQ Sentinel Log Manager) was detected on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.netiq.com/products/sentinel-log-manager/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:sentinel_log_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8443);
dir = '/novelllogmanager';
page = '/views/logon.html';
res = http_send_recv3(method:'GET', item:dir + page, port:port, exit_on_fail:TRUE);

if (res[2] !~ '<title>[^<]*Novell Sentinel Log Manager')
  audit(AUDIT_WEB_FILES_NOT, 'Novell Sentinel Log Manager', port);

# get the version if possible. don't rely on this for version checks on the same branch.
# 1.2.0.2 and 1.2.0.3 both report themselves as 1.2 on the login page
match = eregmatch(string:res[2], pattern:'<p class="version">[^0-1<.]+([0-9.]+)</p>');
if (isnull(match))
  ver = NULL;
else
  ver = match[1];

install = add_install(appname:'novell_slm', port:port, dir:dir, ver:ver);

if (report_verbosity > 0)
{
  report = get_install_report(display_name:'Novell Sentinel Log Manager', installs:install, port:port);
  security_note(port:port, extra:report);
}
else security_note(port);
