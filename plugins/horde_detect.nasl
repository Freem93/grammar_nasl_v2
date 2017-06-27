#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

include("compat.inc");

if (description)
{
  script_id(15604);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");
 
  script_name(english:"Horde Software Detection");
  script_summary(english:"Checks for the presence of Horde");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application framework written in
PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Horde, a PHP-based application framework
from The Horde Project.");
  script_set_attribute(attribute:"see_also", value:"http://www.horde.org/horde/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:horde_application_framework");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");

  script_dependencies("http_version.nasl", "no404.nasl");
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
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);


# Search for version number in a couple of different pages.
files = make_list(
  "/services/help/?module=horde&show=menu",
  "/services/help/?module=horde&show=about",
  "/test.php", "/docs/CHANGES", "/lib/version.phps",
  "/status.php3"
);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/horde", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  foreach file (files)
  {
    # Get the page.
    url = string(dir, file);
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (isnull(res)) exit(0);

    if (
      file == "/docs/CHANGES" &&
      "Horde" >!< res
    ) continue;

    if (egrep(string:res, pattern:"^HTTP/.\.. 200 "))
    {
      icase = FALSE;

      # Specify pattern used to identify version string.
      # - version 3.2
      if ("show=menu" >< file)
      {
        pat = ">Horde ([0-9]+\.[^<]+)</(span|SPAN)>";
      }
      # - version 3.0
      else if ("show=about" >< file)
      {
        pat = ">This is Horde (.+)\.<";
      }
      # - version 2.x
      #   nb: test.php available is itself a vulnerability but sometimes available.
      else if (file == "/test.php")
      {
        pat = "^ *<li>Horde: +(.+) *</li> *$";
        icase = TRUE;
      }
      else if (file == "/docs/CHANGES")
      {
        pat = "^ *v([0-9]+\..+) *$";
      }
      #   nb: another security risk -- ability to view PHP source.
      else if (file == "/lib/version.phps")
      {
        pat = "HORDE_VERSION', '(.+)'";
      }
      # - version 1.x
      else if (file == "/status.php3")
      {
        pat = ">Horde, Version (.+)<";
      }
      # - someone updated files but forgot to add a pattern???
      else
      {
        exit(1, strcat("don't know how to handle file '", file));
      }

      # Try to get the version string.
      ver = NULL;

      matches = egrep(pattern:pat, string:res, icase:icase);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match, icase:icase);
          if (!isnull(item))
          {
            ver = item[1];
            break;
          }
        }
      }

      # If the version is known...
      if (!isnull(ver))
      {
        if (dir == "") dir = "/";
        set_kb_item(
          name:string("www/", port, "/horde"), 
          value:string(ver, " under ", dir)
        );
	set_kb_item(name:"www/horde", value:TRUE);
        if (installs[ver]) installs[ver] += ';' + dir;
        else installs[ver] = dir;

        break;
      }
    }
  }
  # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
  if (max_index(keys(installs)) && !thorough_tests) break;
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity)
  {
    info = "";
    n = 0;
    foreach ver (sort(keys(installs)))
    {
      info += '  Version : ' + ver + '\n';
      foreach dir (sort(split(installs[ver], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir;
        else url = dir + '/';
        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Horde was';
    else report += 's of Horde were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
