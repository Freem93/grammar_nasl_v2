#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63204);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/21 20:57:10 $");

  script_name(english:"ManageEngine Security Manager Plus Detection");
  script_summary(english:"Looks for evidence of ManageEngine Security Manager Plus");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a network security scanner and patch
management software application."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts ManageEngine Security Manager Plus, a web-
based network security scanner and patch management software written in
Java."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.manageengine.com/products/security-manager/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zohocorp:manageengine_security_manager_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 6262);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "ManageEngine Security Manager Plus";
port = get_http_port(default:6262);

url = "/";
initialPage = http_get_cache(item:url, port:port, exit_on_fail:TRUE);
if ('content="1;url=SecurityManager.cc"' >!< initialPage) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

url = '/SecurityManager.cc';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

installs = NULL;
if (
  'document.getElementById("j_username")' >< res[2] && 
  'class="login_admin">First time users use <strong>' >< res[2]
) 
{
  ver_url = '/help/intro/release_notes.html';
  res = http_send_recv3(method:"GET", item:ver_url, port:port, exit_on_fail:TRUE);

  ver_pat = "<h2>(<b>)?Build ([0-9]+)(</b>)?</h2>";
  matches = eregmatch(pattern:ver_pat, string:res[2]);
  if (matches) 
  {
    build = matches[2];
    length = strlen(build);
    if (length == 4) 
    {
      major = build[0];
      minor = build[1];
      version = major + '.' + minor;
    } 
    else if (length == 5) 
    {
      major = build[0]+build[1];
      minor = build[2];
      version = major + '.' + minor;
    } 
    else version = NULL;
  }
  else version = NULL;
   
  # Save info about the install.
  installs = add_install(
    appname  : "manageengine_security_manager",
    port     : port,
    dir      : "",
    ver      : version
  );

}
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : url,
    display_name : appname 
  );
  security_note(port:port, extra:report);
}
else security_note(port);
