#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73317);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/04 00:20:05 $");

  script_name(english:"ELMAH (Error Logging Modules and Handlers) Remotely Accessible");
  script_summary(english:"Tries to access elmah.axd");

  script_set_attribute(attribute:"synopsis", value:"The web server hosts a remotely accessible error logging application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts ELMAH, an error logging application used
with ASP.NET web applications. The elmah.axd script was accessed
remotely without authentication, which could provide detailed
information that could provide a remote, unauthenticated attacker with
sensitive data that could be used to launch further attacks.");
  script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/elmah/");
  script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/elmah/wiki/SecuringErrorLogPages");
  script_set_attribute(attribute:"solution", value:"Restrict access to elmah.axd.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:elmah:elmah");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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
app = "ELMAH";

dirs = make_list(cgi_dirs());
url = "/elmah.axd";
not_access = make_list();
vuln = make_list();
found = FALSE;

foreach dir (dirs)
{
  mod_dir = ereg_replace(pattern:"^/", string:dir, replace:"");

  res = http_send_recv3(
    method : "GET",
    item   : dir + url,
    port   : port,
    exit_on_fail : TRUE
  );

  p = 'Error Log for \\<span id="ApplicationName" title="(.+)/' + mod_dir +
  '"\\>'+mod_dir;

  if (
    (egrep(pattern:'Powered by \\<a href="http://elmah\\.googlecode\\.com/"\\>ELMAH\\</a\\>', string:res[2])) &&
    (egrep(pattern:p, string:res[2]))
  )
  {
    found = TRUE;
    vuln = make_list(vuln, dir+url);
  }
  else if (
    'You are attempting to access ELMAH from a remote machine' >< res[2] &&
    '<title>Forbidden</title>' >< res[2] &&
    # Only flag when checking the root of the application directory to prevent
    # flagging every subdirectory as it's own install
    dir =~ '^^/[^/]+$'
  )
  {
    not_access = make_list(not_access, build_url(qs:dir+url, port:port));
  }
  if (!thorough_tests && (max_index(vuln) != 0)) break;
}

if ((max_index(vuln) == 0) && (max_index(not_access) == 0))
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

if (found)
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(
      items : vuln,
      port  : port
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  not_affected = max_index(not_access);
  if (not_affected == 1) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, not_access[0]);
  else exit(0, "None of the " +app+ " installs (" +join(not_access, sep:", ")+ ") are affected.");
}
