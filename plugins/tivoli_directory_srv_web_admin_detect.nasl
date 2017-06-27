#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58815);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/02/04 20:25:27 $");

  script_name(english:"IBM Tivoli Directory Server Web Administration Tool Detection");
  script_summary(english:"Detects IBM Tivoli Directory Server web interface");

  script_set_attribute(attribute:"synopsis", value:
"A web-based management interface was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"IBM Tivoli Directory Server Web Administration Tool, a web interface
for managing IBM Tivoli Directory Server, was detected on the remote
web server.");

  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/software/tivoli/products/directory-server/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/20");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "websphere_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/WebSphere");
  script_require_ports("Services/www", 9080, 12100);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:12100);

# Make sure the banner looks correct unless we're paranoid.
if (report_paranoia < 2)
{
  server_header = http_server_header(port:port);
  if (isnull(server_header)) 
    audit(AUDIT_WEB_BANNER_NOT, port);
  if ('WebSphere Application Server' >!< server_header) 
    audit(AUDIT_WRONG_WEB_SERVER, port, 'WebSphere Application Server');
}

# The rootdir can be changed if deployed manually
dirs = cgi_dirs();
if (thorough_tests)
{
  dirs = list_uniq(make_list(dirs, '/IDSWebApp'));
}

installs = NULL;
foreach dir (dirs)
{
  url = dir + '/IDSjsp/Login.jsp';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    'Tivoli Directory Server Web Administration Tool</font>' >< res[2] &&
    '&nbsp Console administration login' >< res[2]
  )
  {
    version = NULL;
    pat = '<I>\\[Web application version ([0-9\\.]+)\\]';
    matches = egrep(pattern:pat, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }

    installs = add_install(
      installs:installs, 
      ver:version,
      dir:dir,
      appname:'tivoli_directory_server_web_admin_tool',
      port:port
    );
    if (!thorough_tests) break; 
  }
}

if (isnull(installs)) audit(AUDIT_NOT_DETECT, 'Tivoli Directory Server Web Administration Tool', port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Tivoli Directory Server Web Administration Tool',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port:port);
