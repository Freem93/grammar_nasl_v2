#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38762);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Open Virtual Desktop Detection");
  script_summary(english:"Checks for Open Virtual Desktop");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a virtual desktop application.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Ulteo Open Virtual Desktop, an open source
application delivery solution.");
  script_set_attribute(attribute:"see_also", value:"http://www.ulteo.com/home/en/ovdi/openvirtualdesktop?autolang=en");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/sessionmanager", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  #Request index.php
  url = string(dir, "/index.php");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if (
    'h2 class="centered">Please login with your username</h2>' >< res[2] &&
    '<input type="submit" id="launch_button" value="Log in"' >< res[2] &&
    'powered by <a href="http://www.ulteo.com">' >< res[2]
  )
  {
    ver = "unknown";
    if (dir=="") dir = "/";
    set_kb_item(
      name:string("www/", port, "/OpenVirtualDesktop"),
      value:string(ver, " under ", dir)
    );
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    register_install(
      app_name:"Open Virtual Desktop",
      path:dir,
      version:ver,
      port:port);

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked

    if (installs && !thorough_tests) break;
  }
}

if (max_index(keys(installs)))
{
  if (report_verbosity > 0)
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
    if (n == 1) report += ' of Open Virtual Desktop was';
    else report += 's of Open Virtual Desktop were';
    report += ' detected on the\n' + 'remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
