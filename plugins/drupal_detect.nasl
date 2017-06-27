#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18638);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2017/03/24 20:08:54 $");

  script_name(english:"Drupal Software Detection");
  script_summary(english:"Detects Drupal.");

  script_set_attribute( attribute:"synopsis", value:
"A content management system is running on the remote web server.");
  script_set_attribute( attribute:"description",  value:
"Drupal, an open source content management system written in PHP, is
running on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/");
  script_set_attribute(attribute:"solution", value:
"Ensure that the use of this software aligns with your organization's
security and acceptable use policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);
app = "Drupal";

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/drupal", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs)
{
  ver = UNKNOWN_VER;
  found = FALSE;
  url = dir + "/";
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
      'name="Generator" content="Drupal 8' >< res[2] &&
      '<h3>Your search yielded no results' >!< res[2]       # /search/node FP
  )
  {
    found = TRUE;
    url = dir + "/core/install.php";
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:FALSE);
    matches = eregmatch(pattern:'<span class="site-version">([0-9\\.]+)</span>', string:res[2]);
    if (!empty_or_null(matches))
    {
      ver = matches[1];
    }
  }
  else
  {
    # Grab update.php.
    url = dir + "/update.php?op=info";
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
    # If it looks like Drupal...
    if (
      (
        "main Drupal directory" >< res[2] &&
        (
          "<code>$access_check = FALSE;</code>" >< res[2] ||
          "<code>$update_free_access = FALSE;</code>" >< res[2]
        ) ||
        "set $update_free_access" >< res[2]
      ) ||
      "<h1>Drupal database update</h1>" >< res[2]
    )
    {
      found = TRUE;

      # Try to identify the version number from the changelog.
      # Starting with 8.0, CHANGELOG.txt has moved to core/
      changelog = make_list("/", "/core/");
      foreach path (changelog)
      {
        url = dir + path + "CHANGELOG.txt";
        res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:FALSE);

        # nb: Drupal 1.0.0 was the first version, released 2001-01-15.
        pat = "^Drupal +([1-9].+), 20";
        matches = egrep(pattern:pat, string:res[2]);
        if (!empty_or_null(matches))
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
  if (found)
  {
    register_install(
      app_name : app,
      path     : dir,
      port     : port,
      version  : ver,
      cpe      : "cpe:/a:drupal:drupal",
      webapp   : TRUE
    );
    installs++;

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}

if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(port:port);
