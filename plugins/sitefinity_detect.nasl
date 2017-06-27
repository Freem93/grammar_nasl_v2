#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51118);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_name(english:"Sitefinity CMS Detection");
  script_summary(english:"Looks for Sitefinity CMS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a content management system written in
ASP.NET."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host hosts Sitefinity, a web-based content management
system (CMS) written in ASP.NET."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.sitefinity.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, asp:TRUE);
installs = NULL;
ver_pat  = '<meta name="Generator" content="Sitefinity ([0-9.:]+)';

dirs = cgi_dirs();
if (thorough_tests)
{
  dirs = make_list('/Sitefinity', '/cms', dirs);
  dirs = list_uniq(dirs);
}

foreach url (dirs)
{
  # Find Sitefinity login page
  res = http_send_recv3(
    method          :"GET",
    item            :url+'/sitefinity/login.aspx',
    port            :port,
    exit_on_fail    :TRUE,
    follow_redirect :5
  );
  if( !res[2] || '\r\n\tSitefinity: Login\r\n</title>' >!< res[2])
    continue;

  # Get page with version information
  res = http_send_recv3(
    method          :"GET",
    item            :url + '/',
    port            :port,
    exit_on_fail    :TRUE,
    follow_redirect :5
  );

  ver = NULL;
  if (res[2] && '<meta name="Generator" content="Sitefinity' >< res[2])
  {
    matches = eregmatch(pattern:ver_pat, string:res[2], icase:FALSE);
    if (matches[1]) ver = matches[1];
  }

  installs = add_install(
    installs : installs,
    dir      : url,
    appname  : 'sitefinity',
    ver      : ver,
    port     : port
  );
  if (!thorough_tests) break;
}
if (isnull(installs)) exit(0, "Sitefinity CMS does not appear to be hosted on the web server listening on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Sitefinity CMS',
    installs     : installs,
    item         : '/sitefinity/login.aspx',
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
