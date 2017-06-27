#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50509);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/18 17:45:39 $");

  script_name(english:"FreeNAS Web Detection");
  script_summary(english:"Looks for the FreeNAS login page.");

  script_set_attribute(attribute:"synopsis", value:
"The management interface for a storage system was detected on the
remote web server.");
  script_set_attribute(attribute:"description", value:
"The administrative web interface for FreeNAS was detected on the
remote host. FreeNAS is an open source network attached storage (NAS)
distribution based on FreeBSD.");
  script_set_attribute(attribute:"see_also", value:"http://www.freenas.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freenas:freenas");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80);
header = http_server_header(port:port);

# Unless paranoid, make sure the web server looks like lighttpd
# (which is what the FreeNAS web interface runs on)
# OR nginx (which is what newer FreeNAS runs on)
if (report_paranoia < 2)
{
  if (isnull(header)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);
  if ('lighttpd' >!< tolower(header) && 'nginx' >!< tolower(header)) audit(AUDIT_WRONG_WEB_SERVER, port, "lighttpd or nginx");
}

detected = FALSE;

# old detection
dir = '';
url = dir + '/login.php';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>FreeNAS</title>' >< res[2] &&
  '<td>Username</td>' >< res[2] &&
  '<td>Password</td>' >< res[2]
)
{
  detected = TRUE;

  # Try to get the version if possible
  res = http_send_recv3(method:'GET', item:dir + '/CHANGES', port:port);
  match = eregmatch(string:res[2], pattern:"^FreeNAS ([0-9]+(\.([0-9]+))+)");
  if (match) ver = match[1];
  else ver = NULL;

  register_install(
    app_name:'FreeNAS',
    path:dir,
    port:port,
    version:ver,
    cpe:"cpe:/o:freenas:freenas",
    webapp:TRUE
  );
}

if (!detected)
{
  # only attempt new detection if old detection fails
  # new detection
  dir = '';
  url = dir + '/account/login/?next=/';
  res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
  if (
    'Welcome to FreeNAS' >< res[2]
  )
  {
    detected = TRUE;

    match = eregmatch(string:res[2], pattern:"Welcome to FreeNAS&reg; ([0-9]+(\.([0-9]+))+)");
    if (match) ver = match[1];
    else ver = NULL;

    register_install(
      app_name:'FreeNAS',
      path:dir,
      port:port,
      version:ver,
      cpe:"cpe:/o:freenas:freenas",
      webapp:TRUE
    );
  }
}

if (!detected) audit(AUDIT_NOT_DETECT, 'FreeNAS', port);

report_installs(port:port);
