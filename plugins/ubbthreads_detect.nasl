#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(17315);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"UBB.threads Detection");
  script_summary(english:"Checks for presence of UBB.threads");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a bulletin-board system written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running UBB.threads, a web-based message board
software system written in PHP." );
 script_set_attribute(attribute:"see_also", value:"http://www.ubbcentral.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
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


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/ubbthreads", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  r = http_send_recv3(method:"GET", item:string(dir, "/ubbthreads.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it's UBB.threads.
  if (
    '<a href="http://www.infopop.com/landing/goto.php?a=ubb.threads' >< res ||
    '<A HREF="http://www.ubbthreads.com' >< res
  ) {
    if (dir == "") dir = "/";

    # Try to identify the version number from main page.
    #
    # nb: there have been a couple of different styles used.
    pat = "(^UBB\.threads&trade;|>Powered By UBB\.threads&trade;|>Powered BY UBBThreads) ([^<]+)";
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[2];
        break;
      }
    }
    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    set_kb_item(
      name:string("www/", port, "/ubbthreads"),
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
      info = string("An unknown version of UBB.threads was detected on the remote\nhost under the path '", dir, "'.");
    }
    else {
      info = string("UBB.threads ", ver, " was detected on the remote host under\nthe path '", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of UBB.threads were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra:'\n'+info);
}
