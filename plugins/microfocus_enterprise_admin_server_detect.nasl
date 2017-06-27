#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51838);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_name(english:"Micro Focus Enterprise Administration Server Detection");
  script_summary(english:"Detects Micro Focus Enterprise Administration Server");

  script_set_attribute(
    attribute:"synopsis",
    value:"Micro Focus Enterprise Administration Server is listening on this port."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is a Micro Focus Enterprise Administration
Server."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec34d6f0");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 86);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port   = get_http_port(default:86);
banner = get_http_banner(port:port, exit_on_fail:TRUE);

if ("Server: Micro Focus" >!< banner)
  exit(0, "The banner from the web server listening on port "+port+" does not look have a Server response header mentioning Micro Focus.");

r = http_get_cache(port:port, item:'/', exit_on_fail:TRUE);

if (
  'Micro Focus Enterprise Server Administration</title>' >!< r ||
  '<meta name="author"    lang="en" content="Micro Focus International">' >!< r ||
  "status='Show Enterprise Server Administration Guide'; return true;" >!< r
) exit(0, "The web server listening on port "+port+" does not look like Micro Focus Administration Server.");

# extract and save version number
version = NULL;
ver_pattern = "&nbsp;Version ([0-9.]+)";

foreach line (split(r, keep:FALSE))
{
  if ('<td valign="top" class="custom_small" colspan=2>&nbsp;Version' >< line)
  {
    matches = eregmatch(pattern:ver_pattern, string:line, icase:TRUE);
    if (matches)
    {
      version = matches[1];
      break;
    }
  }
}

installs = add_install(
  appname  : "microfocus_ent_admin_server",
  port     : port,
  dir      : '/',
  ver      : version
);

if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "Micro Focus Enterprise Administration Server"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
