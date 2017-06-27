#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#



include("compat.inc");

if (description) {
  script_id(14629);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"IlohaMail Software Detection");
  script_summary(english:"Checks for the presence of IlohaMail");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a webmail client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IlohaMail, a webmail application that is
based on a stock build of PHP and that does not require either a
database or a separate IMAP library." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4df3051f" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/02");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");

  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for IlohaMail in a couple of different locations.
#
# NB: Directories beyond cgi_dirs() come from a Google search - 
#     'intitle:ilohamail "powered by ilohamail"' - and represent the more
#     popular installation paths currently. Still, cgi_dirs() should 
#     catch the directory if its referenced elsewhere on the target.
if (thorough_tests) dirs = list_uniq(make_list("/webmail", "/ilohamail", "/IlohaMail", "/mail", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/"), port:port);
  if ( isnull(res) || "IlohaMail" >!< res ) continue;

  # For proper as well as quick & dirty installs.
  foreach src (make_list("", "/source")) {
    url = string(dir, src, "/index.php");

    # Get the page.
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (isnull(res)) exit(0);

    if (!http_40x(port:port, code:res)) {
      ver = NULL;

      # Make sure the page is for IlohaMail.
      if (
        egrep(string:res, pattern:'>Powered by <a href="http://ilohamail.org">IlohaMail<') ||
        egrep(string:res, pattern:"<h2>Welcome to IlohaMail") ||
        (
          egrep(string:res, pattern:'<input type="hidden" name="logout" value=0>') &&
          egrep(string:res, pattern:'<input type="hidden" name="rootdir"') &&
          egrep(string:res, pattern:'<input type="password" name="password" value="" size=15')
        )
      ) {
        # Often the version string is embedded in index.php.
        ver = strstr(res, "<b> Version ");
        if (ver != NULL) {
          ver = ver - "<b> Version ";
          if (strstr(res, "</b>")) ver = ver - strstr(ver, "</b>");
          ver = ereg_replace(string:ver, pattern:"-stable", replace:"", icase:TRUE);
        }

        # Handle reporting.
        if (isnull(ver)) {
          ver = "unknown";
        }

        set_kb_item(
          name:string("www/", port, "/ilohamail"),
          value:string(ver, " under ", dir, src)
        );
        if (installs[version]) installs[version] += ';' + dir;
        else installs[version] = dir;
      }
    }
    # nb: it's either a proper or a quick & dirty install.
    if (ver) break;
  }

  # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
  if (installs && !thorough_tests) break;
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(installs)))
    {
      info += '  Version : ' + version + '\n';
      foreach dir (sort(split(installs[version], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir;
        else url = dir + '/';
        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of IlohaMail was';
    else report += 's of IlohaMail were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
