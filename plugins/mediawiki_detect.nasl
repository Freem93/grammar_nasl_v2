#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19233);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/06/12 22:35:12 $");

  script_name(english:"MediaWiki Detection");
  script_summary(english:"Detects MediaWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a wiki application written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running MediaWiki, an open source wiki application
written in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/MediaWiki");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
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

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);
app = "MediaWiki";

# Find where MediaWiki is installed
# Possible (relative) uris for MediaWiki
uris = make_list("", "/wiki");

if (thorough_tests)
{
  uris = make_list(uris, cgi_dirs(), "/Wiki", "/mediawiki");
  uris = sort(list_uniq(uris));
}

ver_capture = "(\d+(\.\d+)*([\d\.]\d*([a-zA-Z]+)?\d*)?)";

# Relative URIs mapped to lists of regexes that extract version info
# regexes[0] verifies page is MediaWiki, regexes[1] extracts version. Reused.
checks = make_array();

# Hold all installs found temporarily regardless of potential duplicates
interim_installs = make_array();

# Look at generator meta tag, available even if page access is user-only.
# Note that this tag did not exist prior to 1.13.0
regexes = make_list();
regexes[0] = make_list(
  '<meta name="generator" content="MediaWiki',
  'id="ca-nstab-main"'
);
regexes[1] = make_list(
  '<meta name="generator" content="MediaWiki ' + ver_capture + '" />'
);
checks["/index.php"] = regexes;

# If we are able to view Special:Recentchanges, we can use the generator tag
# in the atom output. This is available at least since 1.3.0, probably older
regexes = make_list();
regexes[0] = make_list(
  '<generator>MediaWiki '
);
regexes[1] = make_list(
  '<generator>MediaWiki ' + ver_capture + '</generator>'
);
checks["/?title=Special:Recentchanges&feed=atom"] = regexes;

# Cover the case where mediawiki is installed, but not set up.
regexes = make_list();
regexes[0] = make_list(
  "<title>MediaWiki " + ver_capture + " installation</title>",
  "<h1>MediaWiki " + ver_capture + " installation</h1>"
);
regexes[1] = make_list("<h1>MediaWiki " + ver_capture + " installation</h1>");
#  /config prior to 1.17.x, /mw-config thereafter.
checks["/mw-config"] = regexes;

# Detect version from the RELEASE-NOTES file that's part of the archive.
# This will not work on >= 1.18.0 since version information is now
# appended to the file's name (e.g. RELEASE-NOTES-1.18).
regexes = make_list();
regexes[0] = make_list("= MediaWiki release notes =");
regexes[1] = make_list("== MediaWiki " + ver_capture + " ==");
checks["/RELEASE-NOTES"] = regexes;

foreach uri (uris)
{
  # Quick optimization :
  # if a substring of the uri has
  # already been identified as
  # an install, skip it.
  # e.g. if we see /installurl/ and
  # then see /installurl/somepage
  # then don't even check the second one.
  seen = FALSE;
  foreach interim_uri (keys(interim_installs))
    if (stridx(uri, interim_uri) == 0)
      seen = TRUE;

  if (seen) continue;

  foreach check (keys(checks))
  {
    version = NULL;
    ctrl_regex_pass = FALSE;
    res = http_send_recv3(
      item         : uri + check,
      method       : "GET",
      port         : port,
      follow_redirect : 5,
      exit_on_fail : TRUE
    );

    # Is this mediawiki?
    regexes = checks[check];
    foreach regex (regexes[0])
    {
      egrep_res = egrep(string:res[2], pattern:regex);
      if (strlen(egrep_res) > 0)
      {
        ctrl_regex_pass = TRUE;
        break;
      }
    }
    if (!ctrl_regex_pass) continue;

    # If so, get the version
    foreach regex (regexes[1])
    {
      matches = eregmatch(string:res[2], pattern:regex, icase:TRUE);
      if (!isnull(matches))
      {
        version = matches[1];
        break;
      }
    }

    if (!isnull(version))
    {
      interim_installs[uri] = version;
      break;
    }
  }
}

if (max_index(keys(interim_installs)) == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Now that we have a list of potential installs,
# need to 'uniq' them to remove logical duplicates,
# e.g., /url1/page1 and /url1 are the same install,
# so only keep /url1
# 'remove' means set to NULL and ignore later
foreach item (sort(keys(interim_installs)))
{
  foreach item2 (keys(interim_installs))
  {
    if (item != item2 && stridx(item, item2) == 0)
    {
      interim_installs[item] = NULL;
      break;
    }
  }
}

# Store installs
foreach url (keys(interim_installs))
{
  dir = url;
  version = interim_installs[url];

  register_install(
    app_name : app,
    path     : dir,
    port     : port,
    version  : version,
    cpe      : "cpe:/a:mediawiki:mediawiki",
    webapp   : TRUE
  );
}
report_installs(port:port);
