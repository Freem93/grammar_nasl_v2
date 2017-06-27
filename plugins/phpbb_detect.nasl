#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15779);
 script_version("$Revision: 1.22 $");

 script_name(english:"phpBB Detection");
 script_summary(english:"Check for phpBB version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a bulletin-board system written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpBB, a bulletin-board system written in
PHP." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpbb.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/22");
 script_cvs_date("$Date: 2012/08/28 22:35:49 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 
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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpbb", "/phpBB", "/phpBB2", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If phpBB's "Powered by" banner is found...
  if (egrep(pattern:"Powered by <[^>]+>phpBB</a> .*&copy; 20.* phpBB Group", string:res)) {
    # Try to grab the version number from the main page.
    #
    # nb: this won't generally work for versions starting with 2.0.12 but
    #     since we already have index.php we'll try that first.
    pat = "Powered by.*phpBB</a> ([0-9].+) &copy;";
    matches = egrep(pattern:pat, string:res);
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

    # If still unsuccessful, try to grab it from the changelog.
    if (isnull(ver)) {
      r = http_send_recv3(method:"GET", item:dir + "/docs/CHANGELOG.html", port:port, exit_on_fail: 1);
      res = r[2];

      pat = '<meta .+ content="phpBB +([0-9]+\\..+) +Changelog"';
      matches = egrep(pattern:pat, string:res);
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
      if (isnull(ver)) {
        pat = "<title>phpBB +(.+) +:: Changelog</title>";
        matches = egrep(pattern:pat, string:res);
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
      }
      # Try to adjust for an unspecified version number in the title.
      if (ver == "3.0.x" || ver == "2.0.x") {
        ver = NULL;

        pat = ">Changes since (.+)</a></li>";
        matches = egrep(pattern:pat, string:res);
        if (matches) {
          foreach match (split(matches)) {
            match = chomp(match);
            prev_ver = eregmatch(pattern:pat, string:match);
            if (!isnull(prev_ver)) {
              prev_ver = prev_ver[1];
              if (prev_ver == "3.0.1") ver = "3.0.2";
              else if (prev_ver == "3.0.0") ver = "3.0.1";
              else if (prev_ver == "RC-8" && "#v30rc8" >< match) ver = "3.0.0";
              else if (prev_ver == "2.0.22") ver = "2.0.23";
              else if (prev_ver == "2.0.21") ver = "2.0.22";
              else if (prev_ver == "2.0.20") ver = "2.0.21";
              else if (prev_ver == "2.0.19") ver = "2.0.20";
              else if (prev_ver == "2.0.18") ver = "2.0.19";
              else if (prev_ver == "2.0.17") ver = "2.0.18";
              else if (prev_ver == "2.0.16") ver = "2.0.17";
              else if (prev_ver == "2.0.15") ver = "2.0.16";

              break;
            }
          }
        }
      }
    }

    # Generate report and update KB.
    #
    # nb: even if we don't know the version number, it's still useful 
    #     to know that it's installed and where.
    if (dir == "") dir = "/";

    if (isnull(ver)) {
      ver = "unknown";
      info = string(
        "An unknown version of phpBB is installed on the remote host\n",
        "under '", dir, "'.\n"
      );
    }
    else {
      info = string(
        "phpBB version ", ver, " is installed on the remote host\n",
        "under '", dir, "'.\n"
      );
    }

    security_note(port:port, extra:'\n'+info);
    set_kb_item(
      name:string("www/", port, "/phpBB"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name:"www/phpBB", value:TRUE);

    if (!thorough_tests) exit(0);
  }
}
