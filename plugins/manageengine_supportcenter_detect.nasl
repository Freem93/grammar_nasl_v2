#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55447);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_name(english:"ManageEngine SupportCenter Plus Detection");
  script_summary(english:"Looks for evidence of ManageEngine SupportCenter");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a customer support application.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts ManageEngine SupportCenter Plus, a web-
based customer support application written in Java."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.manageengine.com/products/support-center/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:supportcenter_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8080);


installs = NULL;
url = '/';

res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);
if (
  "Please enter both username and password to login"  >< res &&
  egrep(pattern:'class="loginscreenfooter">Copyright &copy; [0-9]+ (AdventNet Inc|ZOHO Corporation)', string:res) &&
  egrep(pattern:'title>.*ManageEngine SupportCenter', string:res)
)
{
  version = NULL;

  build_pat = 'src="/scripts/(common|IncludeSDPScripts)\\.js\\?([0-9]+)"';
  matches = egrep(pattern:build_pat, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:build_pat, string:match);
      if (!isnull(item))
      {
        build = item[2];
        if (strlen(build) == 4)
        {
          version = strcat(build[0], '.', build[1], '.', build[2], ' Build ', build);
          break;
        }
        else if (strlen(build) == 5)
        {
          version = strcat(substr(build, 0, 1), '.', build[2], '.', build[3], ' Build ', build);
          break;
        }
      }
    }
  }

  # Save info about the install.
  installs = add_install(
    appname  : "manageengine_supportcenter",
    installs : installs,
    port     : port,
    dir      : "",
    ver      : version
  );

}
if (isnull(installs))
  exit(0, "ManageEngine SupportCenter Plus was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : url,
    display_name : "ManageEngine SupportCenter"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
