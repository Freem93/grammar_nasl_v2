#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(58832);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/04/26 14:40:56 $");

  script_name(english:"CGIProxy Detection");
  script_summary(english:"Looks for evidence of CGIProxy");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server hosts a web-based proxy script."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts CGIProxy (nph-proxy.cgi), a web-based
proxy script.  This script allows remote users to retrieve any
resource via HTTP, HTTPS, or FTP that is accessible from the server
the script is running on."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.jmarshall.com/tools/cgiproxy/");
  script_set_attribute(
    attribute:"solution",
    value:
"Remove this software if its use does not match your organization's
acceptable use and security policies."
  );
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/23");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:jmarshall:cgiproxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");
include("audit.inc");

port = get_http_port(default:80);

found_dirs = make_list();

files = get_kb_list("www/"+port+"/content/extensions/php");
if (!isnull(files))
{
  foreach file (make_list(files))
  {
    if ("/nph-proxy.cgi" >< file) 
    {
      item = eregmatch(pattern:"(.+)/nph-proxy\.cgi", string:file);
      if (!isnull(item)) found_dirs = make_list(found_dirs, item[1]);
    }
  }
}

installs = NULL;

cgi_dirs = make_list(found_dirs, cgi_dirs(), "/cgi-bin", "/scripts");

foreach dir (list_uniq(cgi_dirs))
{
  url = dir + "/nph-proxy.cgi";
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  if(
    "<h1>CGIProxy</h1>" >< res[2]  &&
    "<title>Start Using CGIProxy</title>" >< res[2]
  )
  {
    version = UNKNOWN;

    item = eregmatch(pattern:">CGIProxy ([0-9\.]+)<", string:res[2]);
    if (!isnull(item)) version = item[1];
    
    installs = add_install(
      dir: dir,
      ver: version,
      appname: 'nph_proxy',
      port: port
    );

    if (!thorough_tests) break;
  }
}

if (max_index(keys(installs)) == 0) audit(AUDIT_NOT_DETECT, "CGIProxy", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name: 'CGIProxy',
    installs: installs,
    port: port,
    item: "/nph-proxy.cgi"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
