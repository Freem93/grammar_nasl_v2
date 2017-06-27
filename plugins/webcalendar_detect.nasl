#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18572);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"WebCalendar Detection");
  script_summary(english:"Checks for presence of WebCalendar");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web-based calendar application
written in PHP." );
 script_set_attribute(attribute:"description", value:
"This script detects whether the remote host is running WebCalendar and
extracts version numbers and locations of any instances found. 

WebCalendar is an open source web calendar application written in PHP." );
 script_set_attribute(attribute:"see_also", value:"http://webcalendar.sourceforge.net/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/28");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:k5n:webcalendar");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Search for WebCalendar.
installs = 0;
foreach dir (cgi_dirs()) {
  # Grab month.php.
  r = http_send_recv3(method:"GET", item:string(dir, "/month.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it looks like WebCalendar...
  #
  # nb: not all sites have a banner so we have to look for 
  #     common elements instead.
  if (
    '<a class="dayofmonth" href="day.php?date=' >< res && 
    '<FORM ACTION="month.php" METHOD="GET" NAME="SelectMonth">' >< res
  ) {
    # Try to identify the version number from the banner, if present.
    pat = '<a title="WebCalendar v(.+) \\(.+\\)" id="programname" ';
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }

    # If that didn't work, try getting it from the changelog.
    if (isnull(ver)) {
      r = http_send_recv3(method:"GET", item:string(dir, "/ChangeLog"), port:port);
      if (isnull(r)) exit(0);
      res = r[2];

      pat = "^Version (.+) \\(";
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/webcalendar"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name:"www/webcalendar", value:TRUE);
    installations[dir] = ver;
    ++installs;

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}


# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    if (ver == "unknown") {
      info = string("An unknown version of WebCalendar was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("WebCalendar ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of WebCalendar were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra: info);
}
