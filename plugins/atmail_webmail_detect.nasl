#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38648);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/04/28 14:01:58 $");

  script_name(english:"Atmail Webmail / AtmailOpen Webmail Detection");
  script_summary(english:"Looks for the Atmail Webmail or AtmailOpen Webmail login page.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application used for webmail.");
  script_set_attribute(attribute:"description", value:
"Atmail Webmail or AtmailOpen Webmail is installed on the remote web
server.");
  script_set_attribute(attribute:"see_also", value:"https://www.atmail.com/products/");
  script_set_attribute(attribute:"solution", value:
"Ensure use of the software conforms with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/30");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:atmail:atmail");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

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

# Atmail has a versioning scheme that needs
# to be normalized, i.e., convert :
# 5.2  to 5.2.0
# 5.41 to 5.4.1
# 6.2  to 6.2.0
# 6.23 to 6.2.3
#
# returns : string - normalized version
#           or same string if no need to
#           normalize
# notes   : versions that have not been
#           seen or may not even exist,
#           e.g., 3.45.3 or 4.55555.1,
#           are ignored and just used as
#           they are since it's not known
#           exactly what they'd represent.
function normalize_version(ver)
{
  local_var pieces, ret_ver;

  # 6.3.x and greater are not, or will not be,
  # affected by this problem
  if (
    ver =~ "^6\.([3-9])($|[^0-9])" ||
    ver =~ "^[7-9]\." ||
    ver =~ "^[1-9][0-9]\." ||
    ver == UNKNOWN_VER
  ) return ver;

  pieces = split(ver, sep:".", keep:FALSE);

  # If like 3, 4, 5
  # Pad it out
  if (max_index(pieces) == 1)
    ret_ver = pieces[0] + '.0' + '.0';
  else if (max_index(pieces) == 2)
  {
    # If like 5.2, pad it out
    if (strlen(pieces[1]) == 1)
      ret_ver = pieces[0] + '.' + pieces[1] + '.0';
    else
      # if like 5.41, split it out
      ret_ver = pieces[0] + '.' + pieces[1][0] + '.' + pieces[1][1];
  }
  else ret_ver = NULL;

  return ret_ver;
}

port = get_http_port(default:80, php:TRUE, embedded: 0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mail", "/atmailopen", cgi_dirs()));
else dirs = list_uniq(make_list(cgi_dirs()));

foreach dir (dirs)
{
  ###############################################
  # 1. Look for regular, recent Atmail installs
  ###############################################
  url = dir + "/index.php";
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: TRUE);

  if (
    ">Powered by Atmail " >< res[2]
    ||
    (
      # The group below has version strings
      # like "</a> - @Mail PHP 5.41"
      '</a> - @Mail' >< res[2]
      &&
      '<TITLE>Login to @Mail' >< res[2]
    )
    ||
    (
      # Cannot get version from the group
      # below, but is useful to identify
      # the install for other (non-ver-check) plugins
      '<input type="hidden" name="MailServer"' >< res[2]
      &&
      '<TITLE>Login to @Mail' >< res[2]
      &&
      '<form action="atmail.php"' >< res[2]
    )
  )
  {
    ver = NULL;
    pattern = ">Powered by Atmail ((demo )?[0-9]+\.[0-9.]+)</a>";
    match = eregmatch(pattern:pattern, string:res[2], icase:TRUE);

    if (match) ver = match[1];

    # If the ver's still unknown, we'll still record the install in the KB.
    if (isnull(ver))
    {
      pattern = "<title>Atmail ([0-9.]+) - Login Page</title>" ;
      matches = eregmatch(pattern:pattern, string:res[2], icase:TRUE);
      if(matches) ver = matches[1];
    }

    # One more try
    if (isnull(ver))
    {
      pattern = "</a> - @Mail (demo |PHP |demo PHP )?([0-9]+\.[0-9.]+)</a>";
      matches = eregmatch(pattern:pattern, string:res[2], icase:TRUE);
      if(matches) ver = matches[1];
    }

    if (isnull(ver)) ver = UNKNOWN_VER;

    # Clean up ver and store if needed
    normalized_ver = normalize_version(ver:ver);
    if (normalized_ver)
    {
      kb_dir = str_replace(string:dir, find:"/", replace:"\");
      set_kb_item(
        name  : 'www/'+port+'/atmail_webmail_normalized_ver/'+kb_dir+'/'+ver,
        value : normalized_ver
      );
    }

    installs = add_install(
      appname  : 'atmail_webmail',
      installs : installs,
      port     : port,
      dir      : dir,
      ver      : ver
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (installs && !thorough_tests) break;
  }
  ###############################################
  # 2. Look for open source AtmailOpen installs
  ###############################################
  else if (
    '<input type="hidden" name="OpenSource" id="OpenSource" value="1">' >< res[2]
    &&
    (
      "<title>Atmail - Login</title>" >< res[2]
      ||
      "<title>AtMail - Login</title>" >< res[2]
    )
    &&
    'title="Search Email"></div>' >< res[2]
  )
  {
    open_installs = add_install(
      appname  : 'atmailopen_webmail',
      installs : installs,
      port     : port,
      dir      : dir,
      ver      : UNKNOWN_VER
    );

    # Scan for multiple installations only if "Thorough tests" is checked.
    if (open_installs && !thorough_tests) break;
  }
  else
  {
    ###############################################
    # 3. Look for 7.x in subdirectory : /admin/
    ###############################################
    url = dir + "/index.php/admin/";
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: TRUE);

    if (
      ">Powered by Atmail " >< res[2]
      &&
      "WebAdmin Login page" >< res[2]
    )
    {
      ver = NULL;
      pattern = ">Powered by Atmail ((demo )?[0-9]+\.[0-9.]+)</a>";
      match = eregmatch(pattern:pattern, string:res[2], icase:TRUE);

      if (match)
        ver = match[1];
      else
      {
        # "/index.php?iosprofile" gives away
        # version info on >= 7.2.2
        ios_url = dir + "/?iosprofile";
        res = http_send_recv3(method:"GET", item:ios_url, port:port, exit_on_fail: TRUE);
        if (
          ">Powered by Atmail " >< res[2]
          &&
          " - Login Page</title>" >< res[2]
        )
        {
          match = eregmatch(pattern:pattern, string:res[2], icase:TRUE);
          if (match) ver = match[1];
        }
      }

      if (isnull(ver)) ver = UNKNOWN_VER;

      # Clean up ver and store if needed
      normalized_ver = normalize_version(ver:ver);
      if (normalized_ver)
      {
        kb_dir = str_replace(string:dir, find:"/", replace:"\");
        set_kb_item(
          name  : 'www/'+port+'/atmail_webmail_normalized_ver/'+kb_dir+'/'+ver,
          value : normalized_ver
        );
      }

      installs = add_install(
        appname  : 'atmail_webmail',
        installs : installs,
        port     : port,
        dir      : dir,
        ver      : ver
      );

      # Scan for multiple installations only if "Thorough tests" is checked.
      if (installs && !thorough_tests) break;
    }
    else
    {
      ###############################################
      # 4. If this is a through scan, look for very
      #    old perl-based installs
      ###############################################
      if (thorough_tests)
      {
        url = dir + "/atmail.pl";
        res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: TRUE);

        # If install is misconfigured, we can get a version
        # so, try that first
        if (
          '<input type="submit" name="Submit" value="Submit Bug Report">' >< res[2]
          &&
          '<input type="hidden" name="version" value="' >< res[2]
          &&
          '<form method="post" action="http://calacode.com/bugtrack.pl">' >< res[2]
        )
        {
          pattern = '<input type="hidden" name="version" value="([0-9][0-9.]+)"';
          matches = egrep(string: res[2], pattern: pattern);

          if (matches)
          {
            ver_match = eregmatch(string: matches, pattern: pattern);
            if (ver_match)
            {
              # Clean up ver and store if needed
              normalized_ver = normalize_version(ver:ver_match[1]);
              if (normalized_ver)
              {
                kb_dir = str_replace(string:dir, find:"/", replace:"\");
                set_kb_item(
                  name  : 'www/'+port+'/atmail_webmail_normalized_ver/'+kb_dir+'/'+ver,
                  value : normalized_ver
                );
              }

              installs = add_install(
                appname  : 'atmail_webmail',
                installs : installs,
                port     : port,
                dir      : dir,
                ver      : ver_match[1]
              );
            }
          }
        }
        else
        {
          # Else, a normal, working install may exist (cannot get version though)
          if (
            eregmatch(
              string  :res[2],
              pattern :'<form.*(action=".*atmail\\.pl".*method="post"|method="post".*action=".*atmail\\.pl")',
              icase   : TRUE
            )
            &&
            (
              'javascript/xp.js"></script>' >< res[2]
              ||
              '<a href="javascript:helpwin(' >< res[2]
            )
          )
          {
            # So far, it looks like Atmail, to be extra
            # sure, check for 'xhtml.pl', a wap/mobile
            # type interface that exists in older installs
            url = dir + "/xhtml.pl";
            res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: TRUE);

            if (
              '<form method="post" action="xhtml.pl">' >< res[2]
              &&
              '<input type="hidden" name="command" value="welcome"/>' >< res[2]
            )
            {
              # Clean up ver and store if needed
              normalized_ver = normalize_version(ver:ver_match[1]);
              if (normalized_ver)
              {
                kb_dir = str_replace(string:dir, find:"/", replace:"\");
                set_kb_item(
                  name  : 'www/'+port+'/atmail_webmail_normalized_ver/'+kb_dir+'/'+ver,
                  value : normalized_ver
                );
              }

              installs = add_install(
                appname  : 'atmail_webmail',
                installs : installs,
                port     : port,
                dir      : dir,
                ver      : ver_match[1]
              );
            }
          }
        }
      }
    }
  }
}

if (isnull(installs) && isnull(open_installs)) audit(AUDIT_WEB_APP_NOT_INST, "Atmail", port);

if (report_verbosity > 0)
{
  closedsource_report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : 'Atmail Webmail'
  );

  opensource_report = get_install_report(
    port         : port,
    installs     : open_installs,
    display_name : 'AtmailOpen Webmail'
  );

  # First quickly check both aren't null; if so,
  # something has gone wrong
  if (isnull(closedsource_report) && isnull(opensource_report))
    audit(AUDIT_FN_FAIL, "get_install_report", "NULL");

  if (!isnull(closedsource_report) && isnull(opensource_report))
    report = closedsource_report;
  else if (isnull(closedsource_report) && !isnull(opensource_report))
    report = opensource_report;
  else
    report = closed_source_report + '\n' + opensource_report;

  security_note(port:port, extra:report);
}
else security_note(port);
