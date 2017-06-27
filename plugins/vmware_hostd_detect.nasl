#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44645);
  script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_name(english:"VMware Host Agent Web Detection");
  script_summary(english:"Looks for evidence of VMware hostd");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web server used by a virtualization
product."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running VMware Host Agent (hostd).  This process
runs a web server used by multiple VMware products."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

res = http_get_cache(item:'/', port:port, exit_on_fail: 1);

ver = NULL;

# VMware ESX/ESXi
if ('<meta name="description" content="VMware ESX' >< res)
{
  pattern = 'document.write\\("<title>" \\+ ([^ ]+) \\+ "</title>"\\);';
  match = eregmatch(string:res, pattern:pattern);

  if (match)
  {
    varname = match[1];
    pattern = 'src="([^"]+welcomeRes\\.js)"';
    match = eregmatch(string:res, pattern:pattern);

    if (match)
    {
      jsurl = '/'+match[1];
      res = http_send_recv3(method:"GET", item:jsurl, port:port, exit_on_fail: 1);

      pattern = 'var '+varname+' = "Welcome to ([^"]+)";';
      match = eregmatch(string:res[2], pattern:pattern);
      if (match) ver = match[1];
    }
  }
}
# VMware Server
else if (
  '<title>VMware Server' >< res &&
  '<meta name="description" content="VMware Server is virtual' >< res
)
{
  pattern = '<title>([^<]+)</title>';
  match = eregmatch(string:res, pattern:pattern);
  if (match) ver = match[1];
}

if (!isnull(ver))
{
  installs = add_install(
    installs:installs,
    dir:'',
    ver:ver,
    appname:'vmware_hostd',
    port:port
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'VMware Host Agent',
      installs:installs,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "VMware Host Agent wasn't detected on port "+port+".");

