#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(18250);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_name(english:"Woltlab Burning Board Detection");
  script_summary(english:"Checks for presence of Burning Board");

 script_set_attribute(attribute:"synopsis", value:"The remote web server is running a messaging forum written in PHP.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Burning Board or Burning Board Lite,
message forum software packages that use PHP and MySQL." );
 script_set_attribute(attribute:"see_also", value:"http://www.woltlab.com/");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/12");

script_set_attribute(attribute:"plugin_type", value:"remote");
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
include("audit.inc");
include("install_func.inc");


port = get_http_port(default:80, php: 1);


# Search for Burning Board.
if (thorough_tests) dirs = list_uniq(make_list("/wbboard", "/board", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
prods = make_array();
foreach dir (dirs)
{
  prod = NULL;
  ver = NULL;

  # Grab the Admin Control Panel, which exists in BBLite and BB 2.x;
  # BB 1.x has "/admin/main.php", which doesn't offer a banner.
  r = http_send_recv3(method:"GET", item:string(dir, "/acp/index.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # Try to identify the product / version from the banner.
  pat = '<p align="center">WoltLab (Burning Board|Burning Board Lite) ([0-9].+) - Admin Control Panel</p>';
  matches = egrep(string:res, pattern:pat);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      info = eregmatch(pattern:pat, string:match);
      if (!isnull(info))
      {
        prod = info[1];
        ver = info[2];
        break;
      }
    }
  }

  # If unsuccessful, try the main page itself (works for BB 3.x and 1.x).
  if (isnull(ver))
  {
    # Grab index.php.
    res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

    # Try to identify the version from the banner.
    pat = "(Forum Software|Forensoftware|Powered by).+>(Burning Board|Burning Board Lite)(&reg;)? ([0-9][^<]+)</(a|b|strong)>";
    matches = egrep(pattern:pat, string:res);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        info = eregmatch(pattern:pat, string:match);
        if (!isnull(info))
        {
          prod = info[2];
          ver = info[4];
          break;
        }
      }
    }

    # If unsuccessful, it may be an older version of Burning Board with a multi-line banner.
    if (isnull(ver))
    {
      pat = '^ +Board (.+) </b> .+<a href="http://www.woltlab.de" target="_blank">WoltLab';
      matches = egrep(pattern:pat, string:res);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver))
          {
            prod = "Burning Board";
            ver = ver[1];
            break;
          }
        }
      }
    }

    # At least try to identify the product (eg, maybe it just doesn't
    # have a copyright notice).
    if (isnull(prod))
    {
      if (
        egrep(string:res, pattern:'<a href="board.php?boardid=[0-9]+(&|&amp;)sid=[^"]">', icase:TRUE) &&
        egrep(string:res, pattern:'<input type="password" name="(l_password|kennwort)"', icase:TRUE)
      )
      {
        # Burning Board Lite doesn't have a calendar.
        if (egrep(pattern:'^ +<a href="calendar.php">', string:res) ) prod = "Burning Board";
        else prod = "Burning Board Lite";
      }

      # Try to grab version from 'acp/lib/inserts.sql'.
      #
      # nb: this may be outdated so use it as a last resort.
      r = http_send_recv3(method:"GET", item:dir + "/acp/lib/inserts.sql", port:port);
      if (isnull(r)) exit(0);
      res = strcat(r[0], r[1], '\r\n', r[2]);

      # Examples:
      #   INSERT INTO bb1_options VALUES (128,0,'boardversion','1.0.2','','','',0);
      #   INSERT INTO bb1_options VALUES (128,0,'boardversion','2.0.2','','','',0);
      pat = "^INSERT INTO bb1_options .+'boardversion','([^']+)',";
      matches = egrep(pattern:pat, string:res);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver))
          {
            ver = ver[1];
            break;
          }
        }
      }

      # If we still don't have a version, just mark it as "unknown".
      if (isnull(ver)) ver = "unknown";
    }
  }

  # If we identified the product...
  if (prod)
  {
    if (dir == "") dir = "/";

    prods[dir] = prod;
    prod = tolower(prod);
    prod = str_replace(string:prod, find:" ", replace:"_");

    set_kb_item(
      name:string("www/", port, "/", prod),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name: "www/"+prod, value: TRUE);
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

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
      foreach dir (sort(split(installs[ver], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir;
        else url = dir + '/';

        register_install(
          app_name:"Woltlab Burning Board",
          path:url,
          version:ver,
          port:port,
          extra:make_array("Variant", prods[dir]));

        info += '\n' +
                '  Version : ' + ver + '\n' +
                '  Variant : ' + prods[dir] + '\n' +
                '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Burning Board was';
    else report += 's of Burning Board were';
    # nb: info starts with a blank line.
    report += ' detected on the remote\n' +
              'host :\n' +
              info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
