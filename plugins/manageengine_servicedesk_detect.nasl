#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55444);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/11/16 21:51:11 $");

  script_name(english:"ManageEngine ServiceDesk Plus Detection");
  script_summary(english:"Checks for evidence of ManageEngine ServiceDesk.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a help desk management application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts ManageEngine ServiceDesk Plus, a web-based
help desk management application written in Java.");
  script_set_attribute(attribute:"see_also", value:"http://www.manageengine.com/help-desk-software.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:servicedesk_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
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
  "src='/scripts/Login.js" >< res &&
  (
    'ZOHO Corporation. All rights reserved.' >< res ||
    '<img src="/images/log_adventnetlogo.gif"' >< res ||
    "getCustomHtml('/custom/login/log_logo.gif'" >< res # build 9115
  ) &&
  egrep(pattern:'title>.*ManageEngine ServiceDesk', string:res)
)
{
  version = NULL;

  # There are two parts to a version -- the main version that's
  # visible and a build, which only seems to be included in URLs.
  build_pat = "'/scripts/Login\.js\?([0-9]+)'";
  ver_pat = "ManageEngine ServiceDesk.+([0-9]+\.[^<']+)(<|')";

  matches = egrep(pattern:ver_pat, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:ver_pat, string:match);
      if (!isnull(item))
      {
        version = item[1];
        break;
      }
    }
  }

  if (!isnull(version))
  {
    matches = egrep(pattern:build_pat, string:res);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:build_pat, string:match);
        if (!isnull(item))
        {
          version += " Build " + item[1];
          break;
        }
      }
    }
  }

  # Save info about the install.
  installs = add_install(
    appname  : "manageengine_servicedesk",
    installs : installs,
    port     : port,
    dir      : "",
    ver      : version
  );

}
if (isnull(installs))
  exit(0, "ManageEngine ServiceDesk Plus was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : url,
    display_name : "ManageEngine ServiceDesk"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
