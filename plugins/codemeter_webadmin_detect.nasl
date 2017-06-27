#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57799);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/23 16:10:43 $");

  script_name(english:"CodeMeter WebAdmin Detection");
  script_summary(english:"Looks for evidence of CodeMeter WebAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a copy protection application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts CodeMeter WebAdmin, a web-based tool for
working with CodeMeter hardware and software based copy protection
technology.");
  script_set_attribute(attribute:"see_also", value:"http://www.wibu.com/codemeter.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wibu:codemeter_runtime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 22350);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "CodeMeter";
installed = FALSE;

port = get_http_port(default:22350, embedded:TRUE);

server_name = http_server_header(port:port);
if (empty_or_null(server_name)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);
if ("WIBU-SYSTEMS" >!< server_name) audit(AUDIT_NOT_DETECT, app, port);

url = '/';

ver_full_pat = "<!-- FileVersion=([0-9][0-9.]+) -->";
ver_ui_pat = "^[ \t]+Version ([0-9][0-9.]+)([a-z])? of (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/[0-9]+/[0-9]+( \(Build ([0-9]+)\))?";
ver_short_pat = "^[ \t]+Version ([0-9][0-9.]+) of (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)";

res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);
if (
  'title>CodeMeter | WebAdmin' >< res ||
  (
    'WIBU-SYSTEMS HTML Served Page' >< res &&
    'onclick="return OnScanNetwork()"' >< res &&
    '<!-- WebAdmin Version -->' >< res
  )
)
{
  version = NULL;
  version_ui = NULL;

  # if we have the full version, use that regardless of the one
  # we extracted from the Server Version.
  matches = egrep(pattern:ver_full_pat, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:ver_full_pat, string:match);
      if (!isnull(item))
      {
        version = item[1];
        break;
      }
    }
  }

  # Use UI pattern as backup if full pattern fails
  # Note: We're checking this regardless of whether or
  # not we already have a version because the UI
  # version contains the format that the user is likely
  # to see in vendor documentation.
  matches = egrep(pattern:ver_ui_pat, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:ver_ui_pat, string:match);
      if (!isnull(item))
      {
        if (isnull(version))
        {
          version = item[1];

          if (isnull(item[2])) version_ui = version;
          else version_ui = strcat(version, item[2]);

          if (isnull(item[5])) item[5] = 0;

          if (isnull(item[2])) last = 500;
          else last = 500 + ord(item[2]) - ord("a") + 1;

          version = join(sep:".", item[1], item[5], last);
        }
        else
        {
          version_ui = item[1];
          if (!isnull(item[2])) version_ui = strcat(version_ui, item[2]);
        }
        break;
      }
    }
  }

  # nb: as a last resort, use the WebAdmin version.
  if (isnull(version) && "WebAdmin Version" >< res)
  {
    matches = egrep(pattern:ver_short_pat, string:res);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:ver_short_pat, string:match);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }
  }

  # Version check plugins will be using the UI
  # version as the display value. Ensure that it
  # contains a value before registering
  if (isnull(version_ui)) version_ui = version;

  # Be more specific with the display version.
  # Try to display as much info about the version
  # as possible.
  if (version_ui != version) version_ui = version_ui + ' (' + version + ')';

  register_install(
    app_name : app,
    display_version : version_ui,
    version : version,
    port    : port,
    path    : "/",
    webapp  : TRUE
  );
  installed = TRUE;
}

if (installed) report_installs(app_name:app, port:port);
else audit(AUDIT_WEB_APP_NOT_INST, app, port);
