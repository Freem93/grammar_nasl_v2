#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15530);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_name(english:"Coppermine Photo Gallery Detection");
  script_summary(english:"Checks for presence of Coppermine");

  script_set_attribute(attribute:"synopsis", value:"The remote web server contains a picture gallery application.");
  script_set_attribute(attribute:"description", value:
"This plugin determines if Coppermine Photo Gallery is installed on the
remote web server and extracts version numbers and locations of any
instances found.

Coppermine is an open source, web-based picture gallery application
written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://coppermine-gallery.net/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:coppermine-gallery:coppermine_photo_gallery");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

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


port = get_http_port(default:80, embedded:0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/cpg", "/coppermine", "/albums", "/gallery", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  url = string(dir, "/db_input.php");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if ("<!--Coppermine Photo Gallery" >< res[2])
  {
    if (dir == "") dir = "/";

    version = NULL;

    # Try to identify the version number from the comment near the start.
    if ("SVN version info:" >< res[2])
    {
      svn_info = strstr(res[2], "SVN version info:");
      svn_info = svn_info - strstr(svn_info, "-->");
      foreach line (split(svn_info, keep:FALSE))
      {
        if ("Coppermine version:" >< line)
        {
          version = strstr(line, "Coppermine version: ") - "Coppermine version: ";
          break;
        }
      }
    }

    # Try to identify the version number from the footer.
    if (isnull(version))
    {
      pat = '<!--Coppermine Photo Gallery ([0-9].*)-->"';
      matches = egrep(string:res[2], pattern:pat);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            version = item[1];
            break;
          }
        }
      }
    }

    # If still unknown, just mark it as "unknown".
    if (isnull(version)) version = "unknown";

    set_kb_item(
      name:string("www/", port, "/coppermine_photo_gallery"),
      value:string(version, " under ", dir)
    );
    if (installs[version]) installs[version] += ';' + dir;
    else installs[version] = dir;

    register_install(
      app_name:"Coppermine Photo Gallery",
      path:dir,
      version:version,
      port:port,
      cpe:"cpe:/a:coppermine-gallery:coppermine_photo_gallery");

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (installs && !thorough_tests) break;
  }
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(installs)))
    {
      info += '  Version : ' + version + '\n';
      foreach dir (sort(split(installs[version], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir;
        else url = dir + '/';

        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Coppermine Photo Gallery was';
    else report += 's of Coppermine Photo Gallery were';
    report += ' detected on the\nremote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
