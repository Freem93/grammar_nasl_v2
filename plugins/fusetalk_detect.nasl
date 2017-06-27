#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48350);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_name(english:"FuseTalk Detection");
  script_summary(english:"Looks for traces of FuseTalk");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a discussion forum software.");
  script_set_attribute(attribute:"description", value:
"FuseTalk, a discussion forum software for ColdFusion or Microsoft
.NET, is running on remote system."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fe1531e");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/fusetalk", "/forum", "/blog","/wiki","/fusetalk/forum", "/forums/forum", "/forum/forum", "/fusetalk/blog", "/fusetalk/wiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = NULL;
version = UNKNOWN_VER;

foreach dir (dirs)
{
  url = dir +  "/search.cfm";  # FuseTalk for ColdFusion
  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

  if (!res[2] || 'function ftgetpermission(' >!< res[2])
  {
    url = dir +  "/search.aspx";  # FuseTalk for .NET
    res = http_send_recv3(port:port, method:"GET", item:url,exit_on_fail:TRUE);
  }

  # Look for some variables/functions/text found on FuseTalk search page
  if (
    'FTVAR_MESSAGETEXTFRM'   >< res[2] &&
    'FTVAR_CATEGORYIDFRM' >< res[2] &&
    (
      'function ftgetpermission(' >< res[2] ||
      'function ftcontexthelp(' >< res[2] ||
      'function ftdeleteownmessage'
    ) &&
    (
      ('FTVAR_STARTDATEFRM' >< res[2] && 'FTVAR_ENDDATEFRM' >< res[2]) ||
      ('FTVAR_USERNAMEFRM' >< res[2] && 'FTVAR_PASSWORDFRM' >< res[2])
    ) &&
    egrep(pattern:">(Forum|Blog|Wiki) Categories<",string:res[2])
  )
  {
    # If we see references to .aspx files, then its running the .NET edition
    if ('search.aspx' >< res[2] && 'categories.aspx' >< res[2])
      app = "fusetalk_net";
    else
      app = "fusetalk_coldfusion";

    # Try to get the version.
    matches = eregmatch(pattern:">FuseTalk (Basic|Standard|Enterprise|Education) Edition *(Evaluation)? *v([0-9.]+)<", string:res[2]);
    if (matches && matches[3]) version = matches[3];

    if (!version)
    {
      matches = eregmatch(pattern:'class="ftbackgroundlinkunder">FuseTalk ([0-9.]+)<', string:res[2]);
      if (matches) version = matches[1];
    }

    installs = add_install(
      appname  : app,
      installs : installs,
      port     : port,
      ver      : version,
      dir      : dir
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (isnull(installs)) exit(0, "Fusetalk was not detected on the web server on port "+port+".");

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "FuseTalk"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
