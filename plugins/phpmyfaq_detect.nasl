#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17297);
  script_version("$Revision: 1.15 $");

  script_name(english:"phpMyFAQ Detection");
  script_summary(english:"Checks for presence of phpMyFAQ");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a FAQ-system script written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpMyFAQ, a multi-lingual database-driven
FAQ system using PHP and MySQL." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyfaq.de/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/09");
 script_cvs_date("$Date: 2015/10/13 15:19:33 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpmyfaq:phpmyfaq");
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

port = get_http_port(default:80, php: 1);


# Search for phpMyFAQ.
if (thorough_tests) dirs = list_uniq(make_list("/faq", "/phpmyfaq", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it's phpMyFAQ.
  if (egrep(pattern:"[pP]owered by .+phpMyFAQ", string:res)) {
    # Try to identify the version number from index.php.
    pat = '[Pp]owered by .*phpMyFAQ.* ([0-9][^"<&]+)';
    matches = egrep(pattern:pat, string:res);
    ver = NULL;
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }
    # If unsuccessful, try to grab it from the README.
    #
    # nb: this isn't always accurate; eg, it reports "1.6.8" for versions 
    #     1.6.8 and 1.6.7!
    if (isnull(ver)) {
      r = http_send_recv3(method:"GET",item:dir + "/docs/README.txt", port:port, exit_on_fail: 1);
      res = strcat(r[0], r[1], '\r\n', r[2]);

      pat = '^phpMyFAQ (.+)$';
      matches = egrep(pattern:pat, string:res);
      if (match) {
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver)) {
            ver = ver[1];
            break;
          }
        }
      }
    }
    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/phpmyfaq"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name:"www/phpmyfaq", value: TRUE);
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
      info = string("An unknown version of phpMyFAQ was detected on the remote host under\nthe path '", dir, "'.");
    }
    else {
      info = string("phpMyFAQ ", ver, " was detected on the remote host under the path\n'", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of phpMyFAQ were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra:'\n'+info);
}
