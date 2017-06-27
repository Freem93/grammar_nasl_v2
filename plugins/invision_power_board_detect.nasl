#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17203);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Invision Power Board Software Detection");
  script_summary(english:"Checks for the presence of Invision Power Board");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Invision Power Board , a suite of PHP
scripts for operating a web-based bulletin board system." );
 script_set_attribute(attribute:"see_also", value:"http://www.invisionboard.com/");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/23");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:invisionpower:invision_power_board");
script_end_attributes();


  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

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
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/ipb", "/invision", "/forums", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs=NULL;
foreach dir (dirs) {
  w = http_send_recv3(method:"GET", item:string(dir, "/index.php"), port:port);
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];
  # Sample banners:
  #   v1.1.2 &copy; 2003 &nbsp;<a href='http://www.invisionpower.com' target='_blank'>IPS, Inc.</a>
  #   v1.2 &copy; 2003 &nbsp;<a href='http://www.invisionpower.com' target='_blank'>IPS, Inc.</a>
  #   v1.3 Final &copy; 2003 &nbsp;<a href='http://www.invisionpower.com' target='_blank'>IPS, Inc.</a>
  #   v1.3.1 Final &copy; 2003 &nbsp;<a href='http://www.invisionpower.com' target='_blank'>IPS, Inc.</a>
  #   v2.0.0 PF 4 &copy; 2005 &nbsp;<a href='http://www.invisionpower.com' target='_blank'>IPS, Inc.</a>
  #   v2.0.3  &copy; 2005 &nbsp;IPS, Inc.
  #   2.2.1 &copy; 2009 &nbsp;<a href='http://www.invisionpower.com' style='text-decoration:none' target='_blank'>IPS, Inc</a>.
  #   3.0.5 &copy; 2009 &nbsp;<a href="http://www.invisionpower.com/" title="IPS Homepage">IPS, <abbr title="Incorporated">Inc</abbr></a>
  pat = "([0-9\.]+.+) &copy; (19|20)[0-9][0-9] .+IPS, .+Inc";
  matches = egrep(pattern:pat, string:res);
  foreach match (split(matches)) {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (ver == NULL) break;
    ver = chomp(ver[1]);
    # Success!
    if (dir == "") dir = "/";

    installs=add_install(
      installs:installs,
      dir:dir,
      ver:ver,
      appname:'invision_power_board',
      port:port
    );

    # nb: only worried about the first match.
    break;
  }
  # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
  if (!thorough_tests && !isnull(installs)) break;
}

if (isnull(installs)) exit(0, "Invision Power Board was not detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:"Invision PowerBoard",
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
