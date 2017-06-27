#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34394);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/13 15:19:31 $");

  script_name(english:"ASG-Sentry CGI Detection");
  script_summary(english:"Looks for ASG-Sentry login page");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script used for network
management.");
  script_set_attribute(attribute:"description", value:
"The remote CGI script is part of ASG-Sentry, a web-based SNMP network
management system.");
  # http://web.archive.org/web/20081217021017/http://www.asg.com/products/product_details.asp?code=SNM&id=96
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0da8508b");
  script_set_attribute(attribute:"solution", value:"Filter incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 6161, 8161);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

# Loop through directories.
#
# nb: only look in "/snmx-cgi" if CGI scanning is disabled.
if (get_kb_item("Settings/disable_cgi_scanning")) dirs = make_list("/snmx-cgi");
else dirs = list_uniq(make_list("/snmx-cgi", cgi_dirs()));


ports = add_port_in_list(list:get_kb_list("Services/www"), port:6161);
ports = add_port_in_list(list:ports, port:8161);

foreach port (ports)
{
  if (!get_port_state(port)) continue;

  installs = make_array();
  foreach dir (dirs)
  {
    # Check whether the FXM program exists.
    r = http_send_recv3(method:"GET",item:string(dir, "/fxm.exe"), port:port);
    if (isnull(r)) break;
    res = r[2];

    # If it does...
    if (
      '<TITLE>ASG-Sentry Login Screen' >< res ||
      '/images/productwheel.jpg alt="ASG, Allen Systems Group' >< res
    )
    {
      ver = NULL;

      pat = ">ASG-Sentry \(tm\) (Agent|Network Manager), (Version |V)([0-9][^<,]+)";
      matches = egrep(string:res, pattern:pat);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[3];
            break;
          }
        }
      }

      # If still unknown, just mark it as "unknown".
      if (isnull(ver)) ver = "unknown";

      if (dir == "") dir = "/";

      set_kb_item(
        name:string("www/", port, "/asg_sentry"),
        value:string(ver, " under ", dir)
      );
      if (installs[ver]) installs[ver] += ';' + dir;
      else installs[ver] = dir;

      register_install(
        app_name:"ASG-Sentry CGI",
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
          info += '  URL     : ' + build_url(port:port, qs:dir+'/fxm.exe') + '\n';
          n++;
        }
        info += '\n';
      }

      report = '\nThe following instance';
      if (n == 1) report += ' of ASG-Sentry  was';
      else report += 's of ASG-Sentry were';
      report += ' detected on the remote host :\n\n' + info;

      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}
