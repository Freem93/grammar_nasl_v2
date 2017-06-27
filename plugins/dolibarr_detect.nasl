#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58745);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_name(english:"Dolibarr Detection");
  script_summary(english:"Checks for the presence of Dolibarr");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains Enterprise Resource Planning (ERP) and
Customer Relationship Management (CRM) software written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Dolibarr, an ERP and CRM software product
written in PHP and with a MySQL back-end.");
  script_set_attribute(attribute:"see_also", value:"http://www.dolibarr.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:dolibarr:dolibarr");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

port = get_http_port(default:80, php:TRUE, embedded:0);

if (thorough_tests) dirs = list_uniq(make_list("/dolibarr", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = NULL;
dirs_found = make_list();

foreach dir (sort(dirs))
{
  # Try to grab dolibarr's login page.
  url = dir+'/';

  w = http_send_recv3(method:"GET",item:url, port:port, exit_on_fail:TRUE);
  if (w[0] !~ '^HTTP/1\\.[01] 200 ') continue;
  if (
    '<td align="center">Dolibarr' >< w[2] &&
    ' class="login" summary="Dolibarr ' >< w[2]
  )
  {
    z = eregmatch(string:w[2], pattern: ' summary="Dolibarr ([0-9.]+)" ');
    if (isnull(z))
    {
      z = eregmatch(string:w[2], pattern: '<td align="a-z]*">Dolibarr ([0-9.]+)</td>');
    }
    if (! isnull(z)) ver = z[1]; else ver = NULL;

    same_install = FALSE;
    foreach dir_found (dirs_found)
    {
      # many sub directory index pages in a dolibarr install look the same
      # so we want to exclude them
      if(dir =~ '^' + dir_found)
        same_install = TRUE;
    }

    if (same_install) continue;

    dirs_found = make_list(dirs_found, dir);

    installs = add_install(
      installs:installs,
      dir:dir,
      ver: ver,
      appname:'dolibarr',
      port:port
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, "Dolibarr was not detected on the web server listening on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Dolibarr',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
