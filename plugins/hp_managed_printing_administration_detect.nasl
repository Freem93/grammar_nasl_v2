#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57699);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_name(english:"HP Managed Printing Administration Detection");
  script_summary(english:"Looks for evidence of HP Managed Printing Administration");

  script_set_attribute(attribute:"synopsis", value:
"A web-based printer administration interface was detected on the
remote host.");
  script_set_attribute(attribute:"description", value:
"HP Managed Printing Administration, a web-based printer
administration interface, was detected on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"http://h20331.www2.hp.com/Hpsub/cache/392596-0-0-225-121.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:managed_printing_administration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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

# Make sure the banner looks correct unless we're paranoid.
if (report_paranoia < 2)
{
  server_header = http_server_header(port:port);
  if (!server_header) exit(0, 'The web server on port '+port+' does not include a server response header in its banner.');
  if ('IIS' >!< server_header) exit(0, 'The web server on port '+port+' isn\'t Microsoft IIS.');
}

# First check determine if hpmpa is installed
version = NULL;
res = http_send_recv3(item:'/hpmpa/default.asp', method:"GET", port:port, exit_on_fail:TRUE);
if ('<title>HP Managed Printing Administration</title>' >< res[2])
{
  # If detection worked, look for the version number.
  res = http_send_recv3(method:"GET", item:'/hpmpa/home/default.asp', port:port, follow_redirect:1, exit_on_fail:1);
  body = res[2];

  pat = '<dd>v([0-9\\.]+)</dd>';
  i1 = stridx(body, '<div id="divVersions">');
  if (i1 >= 0)
  {
    i2 = stridx(body, '<dt>Database version');
    if (i2 > i1)
    {
      body = substr(body, i1, i2);
      match = eregmatch(pattern:pat, string:body);
      if (match)
      {
        version = match[1];
      }
    }
  }
  installs = add_install(
    dir:'/hpmpa',
    ver:version,
    appname:'hp_managed_printing_administration',
    port:port
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'HP Managed Printing Administration',
      installs:installs,
      item:'/default.asp',
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(0, 'HP Managed Printing Administration wasn\'t detected on port ' + port + '.');
