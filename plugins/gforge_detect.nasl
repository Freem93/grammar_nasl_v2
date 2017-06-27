#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42963);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_name(english:"GForge Detection");
  script_summary(english:"Looks for traces of GForge");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP-based project-management and
collaboration software.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running GForge, an open source web-based
project-management and collaboration software."
  );
  script_set_attribute(attribute:"see_also", value:"http://gforge.org/gf/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gforge:gforge");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/gforge", "/gf", "/project", "/projects", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = NULL;

foreach dir (dirs)
{
  # Grab the login page.

  url = dir +  "/account/login.php";
  res = http_send_recv3(port:port, method:"GET", item:url);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if(!egrep(pattern:"[rR]esend [cC]onfirmation [eE]mail",string:res[2]))
  {
    url = dir + '/account/?action=Login';
    res = http_send_recv3(port:port, method:"GET", item:url);
    if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");
  }

  # If it looks like GForge...
  if ( egrep(pattern:"[rR]esend [cC]onfirmation [eE]mail",string:res[2]) &&
     ( ('alt="Powered By GForge' >< res[2] && 'href="http://gforge.org/' >< res[2]) ||
       ('/softwaremap/">Project&nbsp;Tree</a>' >< res[2] && '/snippet/">Code&nbsp;Snippets</a>' >< res[2] && 'src="/themes/gforge/images' >< res[2]) ||
       ('/project/">Projects</a>' >< res[2] && '/snippet/">Snippets</a>' >< res[2] && 'src="/themes/gforge5/images' >< res[2]))
     )
    {
      installs = add_install(
        appname  : "gforge",
        installs : installs,
        port     : port,
        dir      : dir
      );

      # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
      if (!thorough_tests) break;
    }
}
if (isnull(installs)) exit(0, "GForge was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "GForge"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
