#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63333);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/12/24 13:38:48 $");

  script_name(english:"Snare Agent Detection");
  script_summary(english:"Looks for Snare Agent Web Interface");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts an auditing and analysis tool.");
  script_set_attribute(attribute:"description", value:
"The remote web server contains a Snare Agent installation used for
auditing and analysis of system events.  The agent includes an
optionally configured embedded web server used to configure rules for
event monitoring.");
  script_set_attribute(attribute:"see_also", value:"http://www.intersectalliance.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intersect_alliance:snare_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 6161);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:6161, embedded:TRUE);
version = UNKNOWN_VER;

# make sure header looks like Snare unless we're paranoid
if (report_paranoia < 2 )
{
  server_header = http_server_header(port:port);
  if (isnull(server_header)) audit(AUDIT_WEB_BANNER_NOT, port);
  if ("snare" >!< tolower(server_header)) audit(AUDIT_WRONG_WEB_SERVER, port, "Snare");
}

res = http_get_cache(item:"/", port:port, exit_on_fail:TRUE);

pat = NULL;
snare = FALSE;
snare_os = "";

if (
  "<title>Snare Agent for Linux" >< res ||
  "<h1>SNARE for Linux</h1>" >< res
)
{
  snare = TRUE;
  snare_os = "Linux";
  pat = "Version (.+)</center>";
}
else if (
  "<h1>SNARE for Windows" >< res ||
  "<center>SNARE for Windows" >< res
)
{
  snare = TRUE;
  snare_os = "Windows";
  pat = "<CENTER>SNARE Version (.+) Status";
}
else if (
  "<CENTER>Welcome to SNARE for Solaris" >< res
)
{
  snare = TRUE;
  snare_os = "Solaris";
  pat = "Solaris version (.+)</H1>";
}
else if (
  "<CENTER>Welcome to SNARE for AIX" >< res
)
{
  snare = TRUE;
  snare_os = "AIX";
  pat = "AIX version (.+)</H1>";
}
else if (
  "<CENTER>Welcome to SNARE for Irix" >< res
)
{
  snare = TRUE;
  snare_os = "Irix";
  pat = "Irix version (.+)</H1>";
}
# While not an OS, still want to record installs found for Lotus Notes
else if (
  ">Snare for Lotus Notes" >< res
)
{
  snare = TRUE;
  snare_os = "Lotus_Notes";
  pat = "SNARE Version (.+) Status Page";
}

if (!snare) audit(AUDIT_WEB_APP_NOT_INST, "Snare Agent Web Interface", port);

matches = egrep(pattern:pat, string:res);
if (matches)
{
  foreach match (split(matches, keep:FALSE))
  {
    item = eregmatch(pattern:pat, string:match);
    if (!isnull(item))
    {
      version = item[1];
      break;
    }
  }
}
appname = "snare_" + tolower(snare_os);
installs = add_install(
  installs : installs,
  dir      : "",
  appname  : appname,
  ver      : version,
  port     : port
);

if (report_verbosity > 0)
{
  if (snare_os == "Lotus_Notes") snare_os = "Lotus Notes";
  report = get_install_report(
    display_name : 'Snare Agent for ' + snare_os,
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
