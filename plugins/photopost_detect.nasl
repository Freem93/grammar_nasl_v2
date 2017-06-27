#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17648);
  script_version("$Revision: 1.13 $");

  script_name(english:"PhotoPost PHP Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a picture gallery software suite
written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PhotoPost PHP, a picture gallery software
suite written in PHP." );
 script_set_attribute(attribute:"see_also", value:"http://www.photopost.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/30");
 script_cvs_date("$Date: 2015/10/13 15:19:33 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:photopost:photopost_php");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:photopost:photopost_php_pro");
 script_end_attributes();

  script_summary(english:"Checks for presence of PhotoPost PHP");
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


port = get_http_port(default:80, php: 1);


# Search for PhotoPost PHP.
installs = 0;
foreach dir (cgi_dirs()) {
  # Try to pull up index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it's PhotoPost PHP.
  if (egrep(string:res, pattern:"Powered by: <[^>]+>PhotoPost</a> PHP", icase:TRUE)) {
    # Try to identify the version number from index.php.
    # 
    # Sample headers:
    #  'Powered by: <A target="_blank" href="http://www.photopost.com">PhotoPost</a> PHP 3.0.6 <Br>Copyright 2002 All Enthusiast, Inc.'
    #  'Powered by: <A target="_blank" href="http://www.photopost.com">PhotoPost</a> PHP 3.2.1 <Br>Copyright 2002 All Enthusiast, Inc.'
    #  'Powered by: <a target="_blank" href="http://www.qksrv.net/click-xxxxxxx-xxxxxxx">PhotoPost</a> PHP 4.0.1 Copyright 2003 All Enthusiast, Inc.'
    #  'Powered by: <a target="_blank" href="http://www.photopost.com">PhotoPost</a> PHP 4.5.1<br />Copyright 2003 All Enthusiast, Inc.'
    #  'Powered by: <a target="_blank" href="http://www.photopost.com">PhotoPost</a> PHP 4.8d<br />Copyright &copy 2004 All Enthusiast, Inc.'
    #  'Powered by: <a target="_blank" href="http://www.photopost.com">PhotoPost</a> PHP 4.8.2<br />Copyright &copy; 2004 All Enthusiast, Inc.'
    #  'Powered by: <a href="http://www.qksrv.net/click-xxxxxxx-xxxxxxx">PhotoPost</a> PHP 4.86 vB3 Enhanced<br />Copyright 2005 All Enthusiast, Inc.'
    #  'Powered by: <a target="_blank" href="http://www.photopost.com">PhotoPost</a> PHP 5.02 vB3 Enhanced<br />Copyright 2005 All Enthusiast, Inc.'
    ver = NULL;
    pat = "Powered by: <[^>]+>PhotoPost</a> PHP (.+)( C| <Br>C|<br />C)opyright";
    matches = egrep(string:res, pattern:pat, icase:TRUE);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          # nb: we're not particularly interested in vB3 enhancements.
          ver = ver - ' vB3 Enhanced';
          break;
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/photopost"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name:"www/photopost", value:TRUE);
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
      info = string("An unknown version of PhotoPost PHP was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("PhotoPost PHP ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of PhotoPost PHP were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra: info);
}
