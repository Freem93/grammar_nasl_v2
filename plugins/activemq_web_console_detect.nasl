#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45552);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/03/18 19:49:37 $");

  script_name(english:"Apache ActiveMQ Detection");
  script_summary(english:"Looks for the ActiveMQ admin interface.");

  script_set_attribute(attribute:"synopsis", value:
"An administrative console is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"An administrative web interface for Apache ActiveMQ is running on the
remote host. ActiveMQ is an open source messaging and Enterprise
Integration Patterns server system.

Note that starting with version 5.4.0, HTTP Basic Authentication is
available to secure the administrative interface, and starting in
version 5.8.0, this was enabled by default. Consider supplying the
HTTP login credentials in your scan policy to gather version
information from the administrative console.");
  script_set_attribute(attribute:"see_also", value:"http://activemq.apache.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ActiveMQ';
port = get_http_port(default:8161);

installs = 0;
version  = NULL;

if (thorough_tests)
{
  dirs = list_uniq(make_list('/admin', cgi_dirs()));
}
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  found = FALSE;

  url = dir + '/';
  res = http_send_recv3(
    method : "GET",
    item   : url, 
    port   : port,
    exit_on_fail : TRUE
  );

  if (
    res[2] =~ '(Apache )?ActiveMQ( Console)?</title>' &&
    ereg(
      pattern : 'Welcome to the (Apache )?ActiveMQ( Console)?',
      string  : res[2],
      multiline : TRUE
    )
  )
  { 
    found = TRUE;
  }
  else if ('WWW-Authenticate: basic realm="ActiveMQRealm"' >< res[1])
  {
    found = TRUE;
  }

  if (found)
  {
    if (empty_or_null(version))
    {
      # Try and get the version
      if(ereg(pattern:"\<td\>Version\<", string:res[2], multiline:TRUE))
      {
        output = strstr(res[2], "<td>Version");
        match = eregmatch(
          pattern : "\<td\>\<b\>([0-9\.]+)\</b\>\</td\>",
          string  : output
        );
        if (!empty_or_null(match)) version = match[1];
      }
    }

    installs++;
    if (!thorough_tests) break;
  }
}

if (installs == 0)
   audit(AUDIT_WEB_APP_NOT_INST, app, port);
    
if (empty_or_null(version)) version = UNKNOWN_VER;

register_install(
  app_name : app,
  port     : port,
  path     : "/",
  version  : version,
  cpe      : "cpe:/a:apache:activemq",
  webapp   : TRUE
);

report_installs(port:port);
