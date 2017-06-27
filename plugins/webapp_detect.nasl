#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18287);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"WebAPP Detection");
  script_summary(english:"Checks for presence of WebAPP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web portal system written in Perl." );
 script_set_attribute(attribute:"description", value:
"This script detects whether the remote host is running WebAPP and
extracts version numbers and locations of any instances found. 

WebAPP is an open source, web portal system written in Perl." );
 script_set_attribute(attribute:"see_also", value:"http://www.web-app.org/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/17");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value: "cpe:/a:web_app.net:webapp");
 script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Search for WebAPP.
installs = 0;
foreach dir (cgi_dirs()) {
  # Grab index.cgi.
  w = http_send_recv3(method:"GET",item:string(dir, "/index.cgi"), port:port);
  if (isnull(w)) exit(0);
  res = w[2];

  # Try to identify the version number from the Generator meta tag.
  pat = '<meta name="Generator" content="WebAPP (.+)">';
  if (egrep(string:res, pattern:pat, icase:TRUE)) {
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }

    # If that didn't work, try the banner.
    if (isnull(ver)) {
      pat = 'class="webapplink">WebAPP v([^<]+)</a>';
      matches = egrep(pattern:pat, string:res, icase:TRUE);
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
      name:string("www/", port, "/webapp"),
      value:string(ver, " under ", dir)
    );
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
      info = string("An unknown version of WebAPP was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("WebAPP ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of WebAPP were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra: info);
}
