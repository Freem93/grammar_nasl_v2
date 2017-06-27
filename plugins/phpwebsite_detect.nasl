#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17222);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"phpWebSite Detection");
  script_summary(english:"Checks for the presence of phpWebSite");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running phpWebSite, a website content management
system written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://phpwebsite.appstate.edu/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpwebsite:phpwebsite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

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


port = get_http_port(default:80, php: 1);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpwebsite", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it looks like phpWebSite...
  if (egrep(pattern:'(meta name="generator" content="phpWebSite"|powered by.+phpWebSite)', string:res, icase:TRUE))
  {
    # Try to grab the version number from the changelog.
    ver = NULL;

    r = http_send_recv3(method:"GET", item:string(dir, "/docs/CHANGELOG"), port:port, exit_on_fail: 1);
    res = r[2];

    if ("change log for the phpWebSite" >< res)
    {
      pat = "^Version ([0-9]+[^ ]+) *$";
      matches = egrep(pattern:pat, string:res);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            break;
          }
        }
      }
    }
    if (isnull(ver))
    {
      # Try to grab the version number from the changelog.
      r = http_send_recv3(method:"GET", item:string(dir, "/docs/CHANGELOG.txt"), port:port, exit_on_fail: 1);
      res = r[2];

      pat = "phpWebSite-(.+) \(";
      matches = egrep(pattern:pat, string:res);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            break;
          }
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/phpwebsite"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name: "www/phpwebsite", value: TRUE);
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    register_install(
      app_name:"phpWebSite",
      path:dir,
      version:ver,
      port:port,
      cpe:"cpe:/a:phpwebsite:phpwebsite");

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
        info += '  URL     : ' + build_url(port:port, qs:dir+'/') + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of phpWebSite was';
    else report += 's of phpWebSite were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
