#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35786);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/27 20:23:35 $");

  script_name(english:"Zabbix Web Interface Detection");
  script_summary(english:"Detects the Zabbix web interface.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a distributed monitoring system written
in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running the web interface for Zabbix, an open
source distributed monitoring system.");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure the use of this program is in accordance with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

port = get_http_port(default:80, php:TRUE);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/zabbix", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
pre_dir = NULL;
foreach dir (sort(dirs))
{
  pre_dir1 = ereg_replace(pattern:"(/[^/]+/).*", string:pre_dir, replace:"\1");
  new_dir = ereg_replace(pattern:"(/[^/]+/).*", string:dir, replace:"\1");

  if (!isnull(pre_dir1))
    rpeat = ereg(pattern:"^"+pre_dir1+"/", string:new_dir+"/");

  if (rpeat) continue;

  # Request index.php
  url = dir + "/index.php";
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    (
      'href="http://www.zabbix.com/documentation.php" target="_blank">Help' >< res[2] ||
      'href="http://www.zabbix.com/documentation/" target="_blank">Help' >< res[2] ||
      ereg(pattern:'href="http://www.zabbix.com/documentation(/[0-9\\.]+/)?">Help', string:res[2], multiline:TRUE)
    ) &&
    (
      ereg(pattern:'<form method="post" action="index.php(\\?login=1)?"', string:res[2], multiline:TRUE) ||
      '<form action="index.php" method="post">' >< res[2] ||
      '<form action="index.php">' >< res[2]
    )
  )
  {
    # Try to extract the version number from the banner.
    ver = NULL;

    pat = 'ZABBIX( |&nbsp;)([0-9.]+(($|beta|alpha|rc)([0-9]+))?)';
    matches = egrep(pattern:pat, string:res[2], icase:TRUE);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match, icase:TRUE);

        if (!empty_or_null(item))
        {
          ver = item[2];
          ver_split = split(ver, sep:'.', keep:FALSE);
          if(max_index(ver_split) > 2) break;
        }
      }
    }
    if (ver =~ "^([0-9]+\.[0-9]+)($|[^0-9.]|(rc|alpha|beta))")
    {
      ver = ereg_replace(pattern:"^([0-9]+\.[0-9]+)", replace:"\1.0", string:ver);
    }

    if (empty_or_null(ver))
    {
      pat = "jsLoader\.php\?ver=([0-9.]+(($|beta|alpha|rc)([0-9]+))?)";
      match = eregmatch(pattern:pat, string:res[2], icase:TRUE);
      if (!empty_or_null(match))
        ver = match[1];
    }

    # No release notes, so otherwise mark as unknown.
    if (empty_or_null(ver)) ver = UNKNOWN_VER;
    if (dir == "") dir = "/";
    pre_dir = dir;

    installs = add_install(
      appname  : "zabbix",
      installs : installs,
      dir      : dir,
      ver      : ver,
      port     : port
    );
    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if ((max_index(keys(installs)) > 0) && !thorough_tests) break;
  }
}
if (max_index(keys(installs)) == 0) audit(AUDIT_WEB_APP_NOT_INST, "Zabbix frontend", port);

# Report the findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Zabbix frontend",
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
