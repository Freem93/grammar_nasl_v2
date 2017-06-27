#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# GPLv2
#
 

include("compat.inc");

if (description)
{
  script_id(16338);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Mailman Detection");
  script_summary(english:"Checks for the presence of Mailman");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a mailing list management application
written in Python.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mailman, an open source, Python-based
mailing list management package.");
  script_set_attribute(attribute:"see_also", value:"http://www.list.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/10");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:mailman");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 George A. Theall");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mailman", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Search for Mailman's listinfo page.
  url = string(dir, "/listinfo/");
  if (dir == "") dir = "/";

  # Get the page.
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # Find the version number. It will be in a line such as:
  #   <td><img src="/icons/mailman.jpg" alt="Delivered by Mailman" border=0><br>version 2.1.5</td>
  #   <td><img src="/icons/mailman.jpg" alt="Delivered by Mailman" border=0><br>version 2.1.7rc1</td>
  #   <td><a href="http://www.gnu.org/software/mailman/index.html">Delivered by Mailman<br>version 2.1.6</a></td>
  pat = '(alt="|">)Delivered by Mailman[^<]*<br>version ([^<]+)';
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    version = NULL;

    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        version = item[2];
        break;
      }
    }

    # If still unknown, just mark it as "unknown".
    if (isnull(version)) version = "unknown";

    # Success!
    set_kb_item(
      name:string("www/", port, "/Mailman"), 
      value:string(version, " under ", dir)
    );
    if (installs[version]) installs[version] += ';' + dir;
    else installs[version] = dir;

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}


# Report findings.
if (max_index(keys(installs)))
{
  set_kb_item(name:"www/Mailman", value:TRUE);

  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(installs)))
    {
      info += '  Version : ' + version + '\n';
      foreach dir (sort(split(installs[version], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = '/listinfo/';
        else url = dir + '/listinfo/';
        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Mailman was';
    else report += 's of Mailman were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
