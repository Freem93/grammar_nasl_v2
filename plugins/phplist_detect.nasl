#
# (C) Tenable Network Security, Inc.
#
# per phpList maintainer, 'phpList' is official capitalization (12/23/08)


include("compat.inc");

if (description)
{
  script_id(19313);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/04/25 14:31:38 $");

  script_name(english:"phpList Detection");
  script_summary(english:"Checks for presence of phpList");

  script_set_attribute(attribute:"synopsis", value:"The remote web server contains a mailing list manager written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running phpList, a free, web-based mailing list
manager that uses PHP and MySQL.");
  script_set_attribute(attribute:"see_also", value:"https://www.phplist.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tincan:phplist");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

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


port = get_http_port(default:80, php:TRUE);


# Search for phpList.
if (thorough_tests) dirs = list_uniq(make_list("/phplist", "/lists", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Get page for subscribing to a mailing list.
  url = string(dir, "/?p=subscribe");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If the page looks like it's from phpList...
  if ('<link rev="made" href="mailto:phplist%40tincan.co.uk"' >< res[2])
  {
    ver = NULL;

    # Sometimes the version number can be found in a META tag.
    pat = 'meta name="Powered-By" content="PHPlist version (.+)"';
    matches = egrep(string:res, pattern:pat, icase:TRUE);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match, icase:TRUE);
        if (!isnull(item))
        {
          ver = item[1];
          break;
        }
      }
    }
    # Otherwise, try in the "Powered by" line.
    if (isnull(ver))
    {
      pat = "owered by (PHPlist version |.+>phplist</a> v )(.+), &copy;";
      matches = egrep(string:res, pattern:pat);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(string:match, pattern:pat);
          if (!isnull(item))
          {
            ver = item[2];
            break;
          }
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/phplist"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name:"www/phplist", value:TRUE);
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    register_install(
      app_name:"phpList",
      path:dir,
      version:ver,
      port:port,
      cpe:"cpe:/a:tincan:phplist");

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
        if (dir == '/') url = dir;
        else url = dir + '/';
        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of phplist was';
    else report += 's of phplist were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
