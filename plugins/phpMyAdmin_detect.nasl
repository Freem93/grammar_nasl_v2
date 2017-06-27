#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17219);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/04/12 22:33:46 $");

  script_name(english:"phpMyAdmin Detection");
  script_summary(english:"Looks for phpMyAdmin's main.php.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a database management application written
in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running phpMyAdmin, a web-based MySQL
administration tool written in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpMyAdmin", "/phpmyadmin", "/pma", "/", cgi_dirs()));
else dirs = list_uniq(make_list("/", cgi_dirs()));

installs = NULL;

foreach dir (dirs)
{
  if (empty(dir)) continue;

  # Clear cookies and clear our variable for each directory
  clear_cookiejar();
  cookie = NULL;

  url = dir + "/main.php";
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  pat = "^.*(Welcome to .*phpMyAdmin ([0-9]+\.[^<]+)?<.*/h[12]>|parent\.document\.title = .+phpMyAdmin ([0-9]+\.[^']+)';|<h1>Welcome to <bdo.*>phpMyAdmin</bdo>|" + 'PMA_VERSION:"([0-9]+\\.[^"]+)")';
  if (isnull(res[2]))
  {
    url = dir + "/";
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  }

  if ( "phpMyAdmin" >!< res[2] ) continue;

  # Check for cookie value set by phpMyAdmin
  cookies = get_http_cookies_names(name_regex:'phpMyAdmin');
  if (!isnull(cookies))
  {
    cookie = cookies[0];
  }
  matches = egrep(pattern:pat, string:res[2]);

  # Check for matches on login page or our expected cookie
  # Ensure to ignore flagging the setup page as a separate install
  if (matches || (cookie && (res[2] !~ '<title>phpMyAdmin .*setup</title>')))
  {
    ver = NULL;

    # First, try to get the version from main.php
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match, icase:TRUE);
      if (!isnull(item))
      {
        if ("parent.document" >< match) ver = item[3];
        else if ("PMA_VERSION" >< match) ver = item[4];
        else ver = item[2];
        break;
      }
    }

    # If the version wasn't found, try to get it from Documentation.html
    if (!isnull(ver))
    {
      ver = chomp(ver);
    }
    else
    {
      url2 = dir + "/Documentation.html";
      res2 = http_send_recv3(method:"GET", item:url2, port:port, exit_on_fail:TRUE);
      if (!isnull(res2[2]))
      {
        pat = '<title>phpMyAdmin ([^ ]+) - Documentation</title>';
        ver_match = eregmatch(pattern:pat, string:res2[2], icase:TRUE);
        if (ver_match) ver = ver_match[1];
      }
    }

    # If the version wasn't found, try to get it from /doc/html/index.html
    if (isnull(ver))
    {
      url2 = dir + "/doc/html/index.html";
      res2 = http_send_recv3(method:"GET", item:url2, port:port, exit_on_fail:TRUE);
      if (!isnull(res2[2]))
      {
        pat = '<link rel="top" title="phpMyAdmin ([^ ]+) Documentation"';
        ver_match = eregmatch(pattern:pat, string:res2[2], icase:TRUE);
        if (ver_match) ver = ver_match[1];
      }
    }
    # If the version wasn't found in /doc/html/index.html try
    # /docsc/html/index.html (Debian Jessie version 4:4.2.12-2)
    if (isnull(ver))
    {
      url2 = dir + "/docs/html/index.html";
      res2 = http_send_recv3(method:"GET", item:url2, port:port, exit_on_fail:TRUE);
      if (!isnull(res2[2]))
     {
        pat = 'phpMyAdmin ([^ ]+) Documentation</title>';
        ver_match = eregmatch(pattern:pat, string:res2[2], icase:TRUE);
        if (ver_match) ver = ver_match[1];
      }
    }

    installs = add_install(
      installs:installs,
      appname:'phpMyAdmin',
      dir:dir,
      port:port,
      ver:ver
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (installs && !thorough_tests) break;
  }
}

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "phpMyAdmin", port);;

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:"phpMyAdmin",
    installs:installs,
    port:port
  );

  security_note(port:port, extra:report);
}
else security_note(port);
