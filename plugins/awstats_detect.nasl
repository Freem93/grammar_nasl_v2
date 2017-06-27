#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35974);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_name(english:"AWStats Detection");
  script_summary(english:"Looks for AWStats awstats.pl");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a log analysis application written in
Perl.");
 script_set_attribute(attribute:"description", value:
"The remote host is running AWStats, an open source log analysis tool
written in Perl used to generate advanced graphic reports.");
 script_set_attribute(attribute:"see_also", value:"http://www.awstats.org/");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:laurent_destailleur:awstats");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded: 0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/awstats", "/stats", "/awstats/cgi-bin", "/statistics", "/awstats-cgi", "/tools", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = NULL;

foreach dir (dirs)
{
  url = dir + "/awstats.pl" ;
  res = http_send_recv3(method:"GET", item:url, port:port,exit_on_fail:TRUE);

  if(res[0] =~ '^HTTP/1\\.[01] +404 ')
  {
    url = dir + "/awstats.cgi" ;
    res = http_send_recv3(method:"GET", item:url, port:port,exit_on_fail:TRUE);
  }

  if('generator" content="AWStats' >< res[2] ||
     'description" content="Awstats - Advanced Web Statistics for' >< res[2] ||
     'AWStats UseFramesWhenCGI parameter' >< res[2] ||
     'Check config file, permissions and AWStats documentation' >< res[2]
    )
  {
    ver = NULL;
    # Check if we can get the version.
    matches = egrep(pattern:"(content=.AWStats .+ from config file|Advanced Web Statistics ([0-9]+.[0-9]+ *.*) - Created by awstats)", string:res[2]);
    if (matches)
    {
      foreach match (split(matches ,keep:FALSE))
      {
        if ("from config file" >< match)
          pat = "content=.AWStats ([0-9]+.*) from config file";
        else
          pat =  "Advanced Web Statistics ([0-9]+.[0-9]+ *.*) - Created by awstats";

         item = eregmatch(pattern:pat, string:match, icase:TRUE);
         if (!isnull(item) )
         {
            ver = item[1];
            break;
         }
      }
    }

    if(isnull(ver)) ver = "unknown";

    installs = add_install(
        appname  : "AWStats",
        installs : installs,
        port     : port,
        dir      : dir,
        ver      : ver
      );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, "AWStats was not detected on the web server on port "+port+".");

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    #item         : "/awstats.pl", (can be .cgi as well)
    display_name : "AWStats (awstats.pl or awstats.cgi)"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
