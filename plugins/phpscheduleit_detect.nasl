#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34337);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"phpScheduleIt Detection");
  script_summary(english:"Checks for presence of phpScheduleIt");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web-based reservation and scheduling
system written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running phpScheduleIt, an open source web-based
reservation and scheduling application.");
  script_set_attribute(attribute:"see_also", value:"http://phpscheduleit.sourceforge.net/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:brickhost:phpscheduleit");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(
  make_list(
    "/phpscheduleit",
    "/phpScheduleIt",
    "/reservation",
    "/reservations",
    "/schedule",
    "/scheduler",
    "/scheduleit",
    cgi_dirs()
  )
);
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  r = http_send_recv3(method:"GET", item:string(dir, "/roschedule.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it's phpScheduleIt...
  if (
    'Online Scheduler [Read-only Mode]' >< res ||
    (
      'Login to view details and place reservations</a>' >< res &&
      '<a href="http://phpscheduleit.sourceforge.net">phpScheduleIt' >< res
    )
  )
  {
    ver = NULL;

    pat = 'net">phpScheduleIt v([^<]+)</a>';
    matches = egrep(string:res, pattern:pat);
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

    if (isnull(ver))
    {
      # Try to grab the version from the release notes.
      r = http_send_recv3(method:"GET",item:string(dir, "/install/ReleaseNotes.txt"), port:port);
      if (isnull(r)) exit(0);
      res = r[2];

      if ("Release Notes" >< res)
      {
        snippet = res - strstr(res, "Release Notes");
        if ("phpScheduleIt " >< snippet)
        {
          snippet = strstr(snippet, "phpScheduleIt ") - "phpScheduleIt ";
          if (snippet =~ "^[0-9]+\.[0-9.]+")
          {
            ver = chomp(snippet);
          }
        }
      }
    }

    # If still unknown, just mark it as "unknown".
    if (isnull(ver) || ver !~ "^[0-9]\.") ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/phpscheduleit"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name:"www/phpscheduleit", value: TRUE);
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    register_install(
      app_name:"phpScheduleIt",
      path:dir,
      version:ver,
      port:port,
      cpe:"cpe:/a:brickhost:phpscheduleit");

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
    if (n == 1) report += ' of phpScheduleIt was';
    else report += 's of phpScheduleIt were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
