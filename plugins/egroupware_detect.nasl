#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(15720);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2015/10/13 15:19:32 $");

 script_name(english:"eGroupWare Detection");
 script_summary(english:"Detects the presence of eGroupWare");

 script_set_attribute(attribute:"synopsis", value:"A groupware server written in PHP is running on the remote host.");
 script_set_attribute(attribute:"description", value:"The remote host is running eGroupWare, a web-based groupware solution.");
 script_set_attribute(attribute:"see_also", value:"http://www.egroupware.org/");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if (thorough_tests) dirs = list_uniq(make_list("/egroupware", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = dir + '/login.php';

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");
  if (!res[2]) continue;

  if (
    '<title>eGroupWare [login]</title>' >< res[2] ||
    '<meta name="copyright" content="eGroupWare' >< res[2] ||
    egrep(pattern:"<a href=.*www\.egroupware\.org.*eGroupWare</a> ([0-9.])*", string:res[2])
  )
  {
    version = NULL;

    matches = egrep(pattern:".*www.egroupware.org.*eGroupWare</a> ([0-9.]*)</div>.*", string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        version = ereg_replace(pattern:".*www.egroupware.org.*eGroupWare</a> ([0-9.]*)</div>", string:match, replace:"\1");
        break;
      }
    }

    installs = add_install(
      appname  : "egroupware",
      installs : installs,
      port     : port,
      dir      : dir,
      ver      : version
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (isnull(installs)) exit(0, "eGroupWare was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "eGroupWare"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
