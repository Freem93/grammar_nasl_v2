#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35104);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Sun Java System Identity Manager Detection");
  script_summary(english:"Looks for IDM's login page");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a JSP application used for identity
management.");
  script_set_attribute(attribute:"description", value:
"Sun Java System Identity Manager, an enterprise tool for identity
management, is installed on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"http://www.sun.com/software/products/identity_mgr/index.xml");
  script_set_attribute(attribute:"solution", value:"Filter incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");


port = get_http_port(default:8080, embedded: 0);


# Loop through directories.
#
# nb: only look in "/idm" if CGI scanning is disabled.
if (get_kb_item("Settings/disable_cgi_scanning")) dirs = make_list("/idm");
else dirs = list_uniq(make_list("/idm", cgi_dirs()));

installs = make_array();
foreach dir (dirs)
{
  # Try to pull up the login page.
  url = string(dir, "/login.jsp?lang=en&cntry=");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if (
    'title>Identity Manager<' >< res[2] &&
    'action="login.jsp;jsessionid=' >< res[2]
  )
  {
    # Just mark it as "unknown".
    ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/sun_idm"),
      value:string(ver, " under ", dir)
    );
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    register_install(
      app_name:"Sun Java System Identity Manager",
      path:dir,
      version:ver,
      port:port);

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
        if (dir == '/') url = dir + 'login.jsp';
        else url = dir + '/login.jsp';

        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of IDM was';
    else report += 's of IDM were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
