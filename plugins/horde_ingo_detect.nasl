#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22899);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_name(english:"Horde Ingo Software Detection");
  script_summary(english:"Checks for presence of Ingo");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web-based email filter management
application.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Ingo, a PHP-based application from the
Horde Project for managing email filter rules.");
  script_set_attribute(attribute:"see_also", value:"http://www.horde.org/ingo/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("horde_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/horde");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");


port = get_http_port(default:80, php: 1);


# Horde is a prerequisite.
horde_install = get_kb_item(string("www/", port, "/horde"));
if (isnull(horde_install)) exit(0, "The 'www/"+port+"/horde' KB item is missing.");
matches = eregmatch(string:horde_install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(1, "Cannot parse KB entry");
horde_dir = matches[2];


# Search for version number in a couple of different pages.
files = make_list(
  "/services/help/?module=ingo&show=menu",
  "/services/help/?module=ingo&show=about"
);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/ingo", horde_dir+"/ingo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Grab index.php.
  w = http_send_recv3(method: "GET", item:string(dir, "/index.php"), port:port, exit_on_fail: 1, follow_redirect: 0);

  # If we're redirected to a login page...
  #
  # nb: Horde itself redirects to a login page but without the 'url' parameter.
  if ( w[0] =~ "^HTTP/[01.]+ 30[0-9] " &&
       egrep(pattern:"^Location: .*/login\.php\?url=", string:w[1]))
  {
    version = NULL;

    foreach file (files)
    {
      # Get the page.
      if ("/services/help" >< file) url = horde_dir + file;
      else url = dir + file;

      res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

      # Specify pattern used to identify version string.
      #
      # - version 2.1
      if ("show=menu" >< file)
      {
        pat = ">Ingo H[0-9]+ \(([0-9]+\.[^<]+)\)</span>";
      }
      # - version 2.0
      else if ("show=about" >< file)
      {
        pat = '>This is Ingo +(.+)\\.<';
      }
      # - someone updated files but forgot to add a pattern???
      else
      {
        exit(1, strcat("don't know how to handle file '", file));
      }
      # Get the version string.
      matches = egrep(pattern:pat, string:res[2]);
      if (
        matches &&
        (
          # nb: add an extra check in the case of the CHANGES file.
          (file == "/docs/CHANGES" && "Ingo " >< res[2]) ||
          file != "/docs/CHANGES"
        )
      )
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

      # If the version is known...
      if (!isnull(version))
      {
        if (dir == "") dir = "/";
        set_kb_item(
          name:string("www/", port, "/horde_ingo"),
          value:string(version, " under ", dir)
        );
        if (installs[version]) installs[version] += ';' + dir;
        else installs[version] = dir;

        register_install(
          app_name:"Horde Ingo Software",
          path:dir,
          version:version,
          port:port);

        break;
      }
    }
  }
  # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
  if (max_index(keys(installs)) && !thorough_tests) break;
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
        if (dir == '/') url = dir;
        else url = dir + '/';

        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Ingo was';
    else report += 's of Ingo were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
