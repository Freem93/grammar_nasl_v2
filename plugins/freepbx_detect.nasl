#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49997);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/05 20:54:01 $");

  script_name(english:"FreePBX Detection");
  script_summary(english:"Checks for FreePBX.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an open source Asterisk management
interface written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts FreePBX, an open source Asterisk
management application written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://www.freepbx.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freepbx:freepbx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);
app = 'FreePBX';

dirs = cgi_dirs();
if (thorough_tests)
{
  dirs = list_uniq(make_list(dirs, '/html', '/freepbx'));
}

installs = 0;

foreach dir (dirs)
{
  found = FALSE;
  version = UNKNOWN_VER;

  # First try /recordings to see if the app is installed.
  url = dir + '/recordings/index.php';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  if (
    (res[2] =~ '\\<TITLE\\>(FreePBX )?User Portal\\</TITLE\\>') &&
    ('<td>Use your <b>Voicemail Mailbox and Password' >< res[2])
  )
  {
    found = TRUE;
  }
  if (!found)
  {
    res = http_send_recv3(
      method : "GET",
      item   : dir + "/",
      port   : port,
      exit_on_fail : TRUE,
      follow_redirect : 3
    );
    if (
      (res[2] =~ "FreePBX") &&
      ( (res[2] =~ '\\<a href="(admin|panel)/"\\>') ||
        ('alt="FreePBX"' >< res[2])
      )
    ) found = TRUE;
  }

  if (found)
  {
    # If that worked, try to get the version number from /admin/config.php
    # 2.9.x
    item = '/admin/config.php';
    url = dir + item;
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
    if (
      (ereg(pattern:'\\<title\\>.*FreePBX', string:res[2], multiline:TRUE)) &&
      ('<a href="http://www.freepbx.org" target="_blank"' >< res[2])
    )
    {
      pat = '\\<div id="version"\\>.+\\>FreePBX\\</a\\> ([^\\s]+) on';

      value = eregmatch(pattern:pat, string:res[2]);
      if (!empty_or_null(value))
      {
        version = value[1];
      }
      # 2.9.x / 2.10.x and beyond
      if (version == UNKNOWN_VER)
      {
        value = eregmatch(
          pattern : '\\?load_version=([^"]+)"',
          string  : res[2]
        );
        if (!empty_or_null(value))
        {
          version = value[1];
        }
      }
    }
    # 2.11.x +
    # Ensure we don't record a version like .1422301337
    if (version !~ "^(\d)\.(\d)+")
    {
      version = NULL;
      # Check /module.xml. Versions 2.11.x / 12.0
      res = http_send_recv3(
        method  : "GET",
        port    : port,
        item    : dir + "/module.xml",
        exit_on_fail : TRUE
      );
      if ("<rawname>framework<" >< res[2])
      {
        match = eregmatch(
          pattern : '\\<version\\>(.*)\\</version\\>',
          string  : res[2]
        );
        if (!empty_or_null(match)) version = match[1];
      }

      if (isnull(version))
      {
        # Check /admin/CHANGES. Versions 2.11.x
        res = http_send_recv3(
          method : "GET",
          port   : port,
          item   : dir + '/admin/CHANGES',
          exit_on_fail : TRUE
        );
        if ("FreePBX" >< res[2])
        {
          matches = egrep(pattern:"^[0-9\.]+", string:res[2]);
          if (!empty_or_null(matches))
          {
            foreach match (split(matches, keep:FALSE))
            {
              version = match;
              break;
            }

          }
        }
      }
    }

    if (empty_or_null(version)) version = UNKNOWN_VER;

    register_install(
      app_name : app,
      port     : port,
      path     : dir,
      version  : version,
      cpe      : "cpe:/a:freepbx:freepbx",
      webapp   : TRUE
    );
    installs++;
    if (!thorough_tests) break;
  }
}

if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(port:port);
