#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(60061);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/07/19 19:27:21 $");

  script_name(english:"WaveMaker Studio Detection");
  script_summary(english:"Checks web server for wavemaker studio");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web development application is hosted on the remote web server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"WaveMaker Studio, a WYSIWYG development studio, was detected on the
remote host.  This application is a component of the WaveMaker
development platform."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.wavemaker.com/product/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:wavemaker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8094);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8094);
dir = '/wavemaker';
url = dir + '/';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

# If it doesn't look like WaveMaker, it might be because the app is
# protected with basic auth. in newer versions of wavemaker we can check
# for the existence of the configuration tool, which is not protected by basic
# auth (based on the web.xml suggested on the forums), but links to /wavemaker
if ('<title>WaveMaker Studio</title>' >!< res[2] || 'new StudioApplication(' >!< res[2])
{
  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  code = headers['$code'];

  if (code != 401)
    audit(AUDIT_WEB_FILES_NOT, 'WaveMaker Studio', port);

  res = http_send_recv3(method:'GET', item:'/ConfigurationTool/', port:port, exit_on_fail:TRUE);
  if ('<title>StudioConfigure</title>' >!< res[2] || '@import "/wavemaker/lib/boot/boot.css"' >!< res[2])
    audit(AUDIT_WEB_FILES_NOT, 'WaveMaker Studio', port);

  noauth = FALSE;
}
else noauth = TRUE;

version = NULL;

# if studio isn't protected by auth, it should be possible to get the version
if (noauth)
{
  foreach page (make_list('/pages/Studio/Studio.html', '/lib/WMVersion'))
  {
    # versions can look like 6.4.5GA or 4.0.2.24308-Community
    # for now we'll assume only the numeric portion is interesting
    res = http_send_recv3(method:'GET', item:dir + page, port:port);
    match = eregmatch(string:res[2], pattern:"Version: ([\d.]+)");
    if (isnull(match)) continue;
  
    version = match[1];
    break;
  }
}

install = add_install(appname:'wavemaker_studio', ver:version, port:port, dir:dir);
if (noauth)
  set_kb_item(name:'www/' + port + '/wavemaker_studio/noauth', value:TRUE);

if (report_verbosity > 0)
{
  report = get_install_report(display_name:'WaveMaker Studio', installs:install, item:'/', port:port);
  security_note(port:port, extra:report);
}
else security_note(port);

