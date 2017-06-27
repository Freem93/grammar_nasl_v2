#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50430);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/02/19 18:54:50 $");

  script_name(english:"Sawmill Detection");
  script_summary(english:"Looks for Sawmill login page.");

  script_set_attribute(attribute:"synopsis", value:
"A log analysis application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Sawmill, a log analysis tool from Flowerfire Inc., is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.sawmill.net/features.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sawmill:sawmill");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8987, 8988);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "Sawmill";
port = get_http_port(default:8988);
dir = '/';

res = http_get_cache(port:port, item:dir, exit_on_fail:TRUE);
ver = NULL;

if (
  ('<title>Sawmill Login</title>'  ><  res  &&
  '"login-title">Sawmill Login</' ><  res) ||
  ('src="/picts/sawmill_logo.png"' >< res &&
   'class="username-psw text"' >< res) ||
  # 6.x
  ('name="webvars.username"' >< res &&
   'class="title">Sawmill' >< res) ||
  # 7.x
  ('action="Sawmill' >< res &&
   'src="/picts/logo.gif"' >< res)
)
{
  found = TRUE;
  set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

  # Version info can be grabbed from the Server header
  if ("Server: Sawmill/" >< res)
  {
    match = eregmatch(
      pattern : "Server: Sawmill/([0-9\.]+[^\r|\n]+)",
      string  : res,
      icase   : TRUE
    );
    if (!empty_or_null(match[1]))
      ver = match[1];
  }
}

# look for the Sawmill CGI (for versions < 7.x)
if (ver == NULL)
{
  postdata = "volatile.authentication_failed=true&volatile.login=true&" +
    "webvars.username=%24VERSION&webvars.password=" + SCRIPT_NAME - ".nasl" +
    "&submit=Login";

  foreach file (make_list("sawmillcl.exe", "sawmill6cl.exe", ""))
  {
    # If it looks like Sawmill >= 7, try another little trick
    # that works with versions in the range [7.0, 7.1.7].
    res = http_send_recv3(
      method : "POST",
      port   : port,
      item   : dir + file,
      data   : postdata,
      content_type : "application/x-www-form-urlencoded",
      exit_on_fail : TRUE
    );

    match = eregmatch(
      pattern : 'name="webvars\\.username" value="(7\\.[^"]+)"',
      string  : res[2]
    );
    if (!empty_or_null(match))
    {
      found = TRUE;
      ver = match[1];
      break;
    }

    # look for the Sawmill CGI (for versions < 7.x)
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + file + "?ho+{COMPLETE_VERSION}",
      exit_on_fail : TRUE
    );
    match = eregmatch(
      pattern : 'unknown command "Sawmill ([0-9].+)"<',
      string  : res[2]
    );
    if (!empty_or_null(match))
    {
      found = TRUE;
      ver = match[1];
      break;
    }
  }
}

if (found)
{
  if (empty_or_null(ver))
    ver = UNKNOWN_VER;

  register_install(
    path     : dir,
    port     : port,
    version  : ver,
    app_name : app,
    cpe      : 'cpe:/a:sawmill:sawmill',
    webapp   : TRUE
  );
  report_installs(port:port);
}
else audit(AUDIT_WEB_APP_NOT_INST, app, port);
