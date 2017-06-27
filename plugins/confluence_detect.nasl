#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53574);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/05 12:16:31 $");

  script_name(english:"Atlassian Confluence Wiki Detection");
  script_summary(english:"Checks for the Atlassian Confluence Wiki.");

  script_set_attribute(attribute:"synopsis", value:
"A wiki web application is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Atlassian Confluence, a wiki written in Java, is running on the remote
web server.");
  script_set_attribute(attribute:"see_also", value:"https://www.atlassian.com/software/confluence");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/28");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8090);

title_pat = '<title>[\r\n]*Log( In|in)[\r\n -]*Confluence[\r\n -]*</title>';
ver_pat   = 'Powered by <a href="http://www.atlassian.com/software/confluence" class=".*">Atlassian Confluence</a> (<span[^>]+>)?([0-9.]+)(</span>)?';

canon_url_pats = make_list(
  # 3.x
  '<form.*name="loginform" method="POST" action="[^"]*/dologin.action"',
  # 2.x
  '<a.*href="[^"]*/login.action">Log In</a>',
  '<a.*href="[^"]*/forgotuserpassword.action">Forgot password\\?</a>'
);

# Put together a list of directories to search through.
if (thorough_tests)
  dirs = list_uniq(make_list("/confluence", "/wiki", cgi_dirs()));
else
  dirs = make_list(cgi_dirs());

# Search for Confluence.
installs = NULL;
foreach dir (dirs)
{
  version = NULL;
  build = NULL;

  # Try to access page.
  res = http_send_recv3(
    method       : "GET",
    item         : dir + "/login.action",
    port         : port,
    exit_on_fail : TRUE
  );

  # Check the title tag
  if (isnull(eregmatch(string:res[2], pattern:title_pat))) continue;

  # Confluence may be accessible under a few URLs, but its links should
  # point to the canonical URL.
  line = NULL;
  foreach pat (canon_url_pats)
  {
    line = egrep(string:res[2], pattern:pat);
    if (strlen(line) > 0) break;
  }
  if (strlen(line) < 1) continue;

  # Parse path from URL for 3.x
  matches = eregmatch(string:line, pattern:'action="(?:https?://)?[^/]*(.*)/dologin.action"');
  if (isnull(matches))
  {
    # Parse for version 2.x; it does not update form action with base URL,
    # but it does update other links. Try a few different links in case
    # of customization.
    matches = eregmatch(string:line, pattern:'<a.*href="(?:https?://)?[^/]*(.*)/(login|forgotpassword).action"');
    if (isnull(matches)) continue;
  }

  # Ensure the canonical URL matches the directory we're currently
  # checking.
  if (dir != matches[1]) continue;

  # Try to get version
  matches = eregmatch(pattern:ver_pat, string:res[2], icase:FALSE);
  if (!isnull(matches))
    version = matches[2];
  else
    version = UNKNOWN_VER;

  # Get Build Version (if available)
  # https://developer.atlassian.com/display/CONFDEV/Confluence+Build+Information
  build_match = eregmatch(
    pattern : 'ajs-build-number" content="([0-9]+)">',
    string  : res[2], icase : TRUE);

  if (!isnull(build_match)) build = build_match[1];

  if ((isnull(build)) || (build == '')) build = UNKNOWN_VER;

  # We should only have 1 install of confluence on a single port, however
  # 'dir' parameter added to ensure proper handling in any odd case(s)
  set_kb_item(name:"www/"+port+"/confluence/build/" + dir, value:build);

  installs = add_install(
    appname  : "confluence",
    installs : installs,
    port     : port,
    dir      : dir,
    ver      : version
  );

  # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
  if (!thorough_tests && !isnull(installs)) break;
}

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "Confluence", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Confluence',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
