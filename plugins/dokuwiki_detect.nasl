#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24711);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_name(english:"DokuWiki Detection");
  script_summary(english:"Checks for presence of DokuWiki");

  script_set_attribute(attribute:"synopsis", value:"The remote web server contains a wiki application written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running DokuWiki, an open source wiki application
written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://www.dokuwiki.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dokuwiki:dokuwiki");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/doku", "/dokuwiki", "/wiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  url = string(dir, "/doku.php");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If it's DokuWiki.
  if
  (
    'generator" content="DokuWiki' >< res[2] ||
    'title="Driven by DokuWiki"' >< res[2] ||
    'alt="Driven by DokuWiki"' >< res[2]
  )
  {
    version = NULL;

    pat = 'name="generator" content="DokuWiki (Release [^"]+)"';
    matches = egrep(pattern:pat, string:res);
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

    if (isnull(version))
    {
      url = string(dir, "/VERSION");
      res = http_send_recv3(method:"GET", item:url, port:port);
      if (isnull(res)) exit(0);

      if (res[2] =~ "^2[0-9]{3}-[0-9]{2}-[0-9]{2}") version = "Release " + chomp(res[2]);
    }

    # If still unknown, just mark it as "unknown".
    if (isnull(version)) version = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/dokuwiki"),
      value:string(version, " under ", dir)
    );
    if (installs[version]) installs[version] += ';' + dir;
    else installs[version] = dir;

    register_install(
      app_name:"DokuWiki",
      path:dir,
      version:version,
      port:port,
      cpe:"cpe:/a:dokuwiki:dokuwiki");

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(installs)))
    {
      info += '  Version : ' + version + '\n';
      foreach dir (sort(split(installs[version], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir + 'doku.php';
        else url = dir + '/doku.php';

        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of DokuWiki was';
    else report += 's of DokiWiki were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
