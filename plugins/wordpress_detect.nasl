#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18297);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/09 20:35:28 $");

  script_name(english:"WordPress Detection");
  script_summary(english:"Checks for presence of WordPress.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server contains a blog application written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WordPress, a free blog application written
in PHP with a MySQL back-end.");
  script_set_attribute(attribute:"see_also", value:"http://www.wordpress.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

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

# Parse a redirect and grab the location if the redirect
# is used for language support
function check_wp_redirect(res, dir)
{
  local_var loc, parse_loc, redir;

  if (
    (ereg(pattern:"lang", string:res[1], icase:TRUE, multiline:TRUE)) ||
    (ereg(pattern:"translate", string:res[2], icase:TRUE, multiline:TRUE))
  )
  {
    loc = egrep(string: res[1], pattern: '^Location:', icase: 1);
    if (empty_or_null(loc)) return NULL;

    parse_loc = eregmatch(
      string  : chomp(loc),
      pattern : '^Location:[ \t]*([^ \t].*)',
      icase   : TRUE
    );
    if (empty_or_null(parse_loc)) return NULL;

    # /blog/en/
    redir = eregmatch(pattern:"("+dir+"/[a-zA-Z]{2}/)", string:parse_loc[1]);
    if (!empty_or_null(redir[1]))
    {
      dir = redir[1];
      return dir;
    }
    else
    {
      # /blog/?lang=en
      redir = eregmatch(pattern:"("+dir+"/\?lang=[a-zA-Z]{2})", string:parse_loc[1]);
      if (!empty_or_null(redir[1]))
      {
        dir = redir[1];
        return dir;
      }
    }
  }
  return NULL;
}

# Test the redirect URL we obtained above and ensure
# we get a 200 response, otherwise we will just keep the
# original response to the initial request and parse that.
function parse_wp_redirect(res, dir)
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir,
    exit_on_fail : TRUE
  );
  if (res[0] =~ '^HTTP/1\\.[01] +200')
    return res;

  return res;
}

port = get_http_port(default:80, php: TRUE);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/wordpress", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
pre_dir = NULL;
foreach dir (sort(dirs))
{
  # Check to make sure we don't flag an install under a previous directory
  # name to prevent double reporting a single install in cases where
  # permalinks are not set to 'Default'
  rpeat = FALSE;

  pre_dir1 = ereg_replace(pattern:"(/[^/]+/).*", string:pre_dir, replace:"\1");
  new_dir = ereg_replace(pattern:"(/[^/]+/).*", string:dir, replace:"\1");

  if (!isnull(pre_dir1))
    rpeat = ereg(pattern:"^"+pre_dir1+"/", string:new_dir+"/");

  if (rpeat) continue;

  found = FALSE;
  backup_chk = FALSE;
  extra = NULL;

  res = http_send_recv3(
    method       : "GET",
    item         : dir + "/",
    port         : port,
    exit_on_fail : TRUE
  );

  if (res[0] =~ '^HTTP/1\\.[01] +30[1237] ')
  {
    redir_path = check_wp_redirect(res:res, dir:dir);
    if (!isnull(redir_path))
    {
      extra["Redirect"] = redir_path;
      res = parse_wp_redirect(res:res, dir:redir_path);
    }
  }

  ver = UNKNOWN_VER;

  if (
    egrep(pattern:"src=('" + '|")([a-zA-Z0-9\\./_:-]+)/wp-content/themes/', string:res[2]) ||
    egrep(pattern:'\\<link rel=("|' + "')wlwmanifest('|" + '") type=("|' + "')application/wlwmanifest\+xml('|" + '")', string:res[2]) ||
    egrep(pattern:"<link rel=('|" + '")pingback("|' + "')", string:res[2])
  ) backup_chk = TRUE;

  # Try to identify the version number from the Generator meta tag.
  pat = '<meta name="generator" content="WordPress (.+)" />';
  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        found = TRUE;
        ver = item[1];
        break;
      }
    }
  }

  # If that didn't work, look in readme.html.
  if (!matches && backup_chk)
  {
    res2 = http_send_recv3(
      method       : "GET",
      item         : dir + "/readme.html",
      port         : port,
      exit_on_fail : TRUE
    );
    if ("<title>WordPress" >< res2[2])
    {
      found = TRUE;
      pats = make_list('^\\s+Version (.+)</h1>','^\\s+<br /> Version (.+)');
      foreach pat (pats)
      {
        matches = egrep(pattern:pat, string:res2[2]);
        if (matches)
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = eregmatch(pattern:pat, string:match);
            if (!isnull(item))
            {
              ver = item[1];
              break;
            }
          }
        }
      }
    }
  }

  if (!found && backup_chk)
  {
    # Check /wp-includes/js/quicktags.js.  File existed since 2.0
    pat1 = 'new edLink\\(("|' + "'" +')WordPress("|' + "')";
    pat2 = 'new edLink\\(("|' + "'" + ')alexking.org("|' + "')";

    res = http_send_recv3(
      method : "GET",
      item   : dir + "/wp-includes/js/quicktags.js",
      port   : port,
      exit_on_fail : TRUE
    );

    if (
      (
        egrep(pattern:pat1, string:res[2]) &&
        egrep(pattern:pat2, string:res[2])
      ) ||
      '* This is the HTML editor in WordPress' >< res[2]
    ) found = TRUE;

    else
    {
      # Check /wp-includes/js/quicktags.dev.js. Some cases such as 3.3.x and
      # 3.4.x versions contained more identifiable tags in this file instead
      res = http_send_recv3(
        method : "GET",
        item   : dir + "/wp-includes/js/quicktags.dev.js",
        port   : port,
        exit_on_fail : TRUE
      );

      if (
        (
          egrep(pattern:pat1, string:res[2]) &&
          egrep(pattern:pat2, string:res[2])
        ) ||
        (
          '* This is the HTML editor in WordPress' >< res[2] &&
          'http://www.alexking.org' >< res[2]
        )
      ) found = TRUE;
    }
  }

  if (found)
  {
    register_install(
      app_name : 'WordPress',
      path     : dir,
      port     : port,
      version  : ver,
      cpe      : "cpe:/a:wordpress:wordpress",
      webapp   : TRUE,
      extra_no_report : extra
    );
    installs++;
    pre_dir = dir;
    if (!thorough_tests) break;
  }
}

if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, "WordPress", port);

# Report findings.
report_installs(port:port);
