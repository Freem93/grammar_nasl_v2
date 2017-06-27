#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19941);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"TWiki Detection");
  script_summary(english:"Checks for presence of TWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Wiki system written in Perl.");
  script_set_attribute(attribute:"description", value:
"The remote host is running TWiki, an open source wiki system written
in Perl.");
  script_set_attribute(attribute:"see_also", value:"http://twiki.org");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"risk_factor", value:"None");
  
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/06");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value: "cpe:/a:twiki:twiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80);
app = "TWiki";

# Search through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/twiki/bin", "/wiki/bin", "/cgi-bin/twiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

num_installs = 0;
pre_dir = NULL;

foreach dir (alpha_sort(dirs))
{
  # Check to make sure we don't flag an install under a previous directory
  # name to prevent double reporting a single install
  rpeat = FALSE;

  pre_dir1 = ereg_replace(pattern:"(/[^/]+/).*", string:pre_dir, replace:"\1");
  new_dir = ereg_replace(pattern:"(/[^/]+/).*", string:dir, replace:"\1");

  if (!isnull(pre_dir1))
    rpeat = ereg(pattern:"^"+pre_dir1+"/", string:new_dir+"/");
  if (rpeat) continue;

  alt_found = FALSE;
  # Try to get the TWiki Web home page.
  res = http_send_recv3(
    method       : "GET",
    item         : dir + "/view/TWiki/WebHome",
    port         : port,
    exit_on_fail : TRUE
  );

  if (res[0] =~ "(404|301|302)")
  {
    res = http_send_recv3(
      method       : "GET",
      item         : dir + "/",
      port         : port,
      exit_on_fail : TRUE
    );
  
    if ('alt="Powered by TWiki"' >< res[2])
    {
      alt_found = TRUE;
      # Get and follow link the WebHome
      match = eregmatch(
        pattern: '\\|\\s+<a href="(.*/TWiki/WebHome)">',
        string  : res[2]
      );
      if (!empty_or_null(match))
      {
        res = http_send_recv3(
          method       : "GET",
          port         : port,
          item         : match[1],
          exit_on_fail : TRUE
        );
      }
    }
  }

  # If it looks like TWiki...
  if (
    'alt="This site is powered by the TWiki' >< res[2] ||
    '<div class="twikiMain"><div class="twikiToolBar"><div>' >< res[2] ||
    '/view/TWiki/WebHome?skin=print">' >< res[2] ||
    'class="twikiFirstCol">' >< res[2] ||
    alt_found
  )
  {
    # Ignore FP with 'oops' error page
    if ('patternOopsPage"' >< res[2]) continue;

    # Try to pull out the version number, build date, and build number.
    ver = UNKNOWN_VER;
    build_date = UNKNOWN_VER;
    build_number = UNKNOWN_VER;

    pat = "This site is running TWiki version <strong>(.+)</strong>";
    matches = egrep(pattern:pat, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        ver_pat = "version <strong>TWiki-([0-9\.\-A-Za-z]+)";
        item = eregmatch(pattern:ver_pat, string:match);
        if (!isnull(item)) ver = item[1];

        date_pat = "([0123][0-9] [A-Za-z]{3} [12][0-9]+)";
        item = eregmatch(pattern:date_pat, string:match);
        if (!isnull(item)) build_date = item[1];

        build_pat = "build ([0-9]+)</strong>";
        item = eregmatch(pattern:build_pat, string:match);
        if (!empty_or_null(item))
        {
          build_number = item[1];
          break;
        }
      }
    }

    # Versions 6.x.
    matches2 = egrep(pattern:"<li> Installed: TWiki-(.+)", string:res[2]);
    if (matches2)
    {
      foreach match (split(matches2, keep:FALSE))
      {
        ver_pat = "Installed: TWiki-([0-9\.\-A-Za-z]+)";
        item = eregmatch(pattern:ver_pat, string:match);
        if (!empty_or_null(item)) ver = item[1];

        date_pat = "([0123][0-9] [A-Za-z]{3} [12][0-9]+)";
        item = eregmatch(pattern:date_pat, string:match);
        if (!empty_or_null(item)) build_date = item[1];

        build_pat = "build ([0-9]+),";
        item = eregmatch(pattern:build_pat, string:match);
        if (!empty_or_null(item))
        {
          build_number = item[1];
          break;
        }
      }
    }

    # Versions prior to 4.0.5 used the date as the displayed version
    if (ver == UNKNOWN_VER) ver = build_date;

    if (!alt_found)
    {
      # Add /view to directory to ensure report URL reaches a TWiki page
      # in cases where we didn't follow a direct link
      dir = dir + "/view";
    }

    installs = register_install(
      app_name : app,
      path     : dir,
      version  : ver,
      port     : port,
      webapp   : TRUE,
      cpe      : "cpe:/a:twiki:twiki",
      extra_no_report : make_array(
        "Build Date", build_date,
        "Build Number", build_number)
    );
    num_installs++;
    pre_dir = dir;
    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (num_installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(port:port);
