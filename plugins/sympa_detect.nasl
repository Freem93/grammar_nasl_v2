#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31725);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Sympa Detection");
  script_summary(english:"Checks for presence of Sympa");

  script_set_attribute(attribute:"synopsis", value:"The remote web server contains a mailing list application.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Sympa, an open source mailing list software
application.");
  script_set_attribute(attribute:"see_also", value:"http://www.sympa.org/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sympa:sympa");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/sympa", "/lists", "/wws", "/wwsympa", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  url = string(dir, "/remindpasswd");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If it's Sympa...
  if
  (
    'name="action_sendpasswd"' >< res[2] &&
    (
      'href="http://www.sympa.org">Powered by Sympa' >< res[2] ||
      'Powered by <a href="http://www.sympa.org/">Sympa' >< res[2] ||
      '<em>Powered by Sympa</em>' >< res[2] ||
      'powered by <a href="http://www.sympa.org/">Sympa</a>' >< res[2] ||
      '/logo-s.png" ALT="Sympa ' >< res[2]
    )
  )
  {
    ver = NULL;

    pat = '(>Powered by |Powered by <[^>]+>|<em>|alt=")Sympa v?([^<"]+)(</a>|<font>|")';
    matches = egrep(pattern:pat, string:res[2], icase:TRUE);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match, icase:TRUE);
        if (!isnull(item))
        {
          ver = item[2];
          break;
        }
      }
    }

    # If still unknown, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/sympa"),
      value:string(ver, " under ", dir)
    );
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    register_install(
      app_name:"Sympa",
      path:dir,
      version:ver,
      port:port,
      cpe:"cpe:/a:sympa:sympa");

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
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
    if (n == 1) report += ' of Sympa was';
    else report += 's of Sympa were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
