#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{
  script_id(46197);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_name(english:"Ektron CMS400.NET Detection");
  script_summary(english:"Looks for traces of Ektron CMS400.NET");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an ASP-based content management
software.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Ektron CMS400.NET, a content management
software used to create, deploy, and manage websites.");
  script_set_attribute(attribute:"see_also", value:"http://www.ektron.com/cms/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, asp:TRUE);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/cms400min", "/cms", "/cms400", "/cms400.net", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = NULL;

foreach dir (dirs)
{
  # Grab the login page.
  item =  "/login.aspx";
  url = dir + item;
  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
 
  if ('<link id="EktronEditorsMenuCSS"' >!< res[2])
  {
    item = "/CMSlogin.aspx";
    url = dir + item;
    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
  }
  
  # If it looks like Ektron CMS
  if (
    ('<link id="EktronEditorsMenuCSS"' >< res[2] || '<link id="EktronRegisteredCss" rel="stylesheet"' >< res[2]) && 
    "/WorkArea/images/application/btn_login.gif' alt='Click here to log in"   >< res[2] &&
    "/WorkArea/images/application/btn_help.gif' alt='Click here to get help'" >< res[2]
  )
  {
    version = UNKNOWN_VER;

    installs = add_install(
      appname  : "cms400",
      installs : installs,
      port     : port,
      dir      : dir,
      ver      : version
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "Ektron CMS400.NET", port);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "Ektron CMS400.NET",
    item         : item
  );
  security_note(port:port, extra:report);
}
else security_note(port);
