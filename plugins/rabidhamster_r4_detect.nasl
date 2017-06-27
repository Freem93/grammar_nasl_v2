#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61460);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/09 16:31:04 $");

  script_name(english:"RabidHamster R4 Detection");
  script_summary(english:"Detects R4 embedded web server");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is used for editing animated 3D graphics
that react to music.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running R4, a standalone OpenGL accelerated
program used to produce animated 3D graphics that twist and turn to
music.  R4 contains a built-in web server that allows you to control
the visuals that are produced from a remote device.");
  script_set_attribute(attribute:"see_also", value:"http://r4.rabidhamster.org/R4/main.php");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:rabidhamster:r4");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# R4 uses port 8888 by default
port = get_http_port(default:8888, embedded:TRUE);

# make sure header looks like R4 unless we're paranoid
if (report_paranoia < 2 )
{
  server_header = http_server_header(port:port);
  if (isnull(server_header)) exit(0, "The web server listening on port " + port + " does not send a Server response header.");
  if ("R4 Embedded Server" >!< server_header) audit(AUDIT_WRONG_WEB_SERVER, port, "R4");
}

res1 = http_get_cache(item:"/", port:port, exit_on_fail:TRUE);
if ("<title>R4 Remote Control</title>" >!< res1) audit(AUDIT_WEB_APP_NOT_INST, "R4", port);

version = UNKNOWN_VER;

# Grab version info from about page
url = "/left_about.html";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  "<b>R4 Statistics" >< res[2] &&
  "<p>This is the web-based remote control for R4." >< res[2]
)
{
  matches = egrep(pattern:"^[0-9]+\.[0-9.]+($|[^0-9])*<br>$", string:res[2]);
  if (matches)
  {
    foreach match (split(matches, sep:"<br>", keep:FALSE))
    {
      item = eregmatch(pattern:"^[0-9]+\.[0-9.]+($|[^0-9])*", string:match);
      if (!isnull(item)) 
      {
        version = item[0];
        break;
      }
    }
  }
}
installs = add_install(
  dir      : "/",
  appname  : 'rabidhamster_r4',
  ver      : version,
  port     : port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'R4',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
