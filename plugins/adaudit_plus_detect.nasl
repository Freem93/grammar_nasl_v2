#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46788);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:21 $");

  script_name(english:"ManageEngine ADAudit Plus Detection");
  script_summary(english:"Looks for the ADAudit login page");

  script_set_attribute(attribute:"synopsis",value:
"An Active Directory change auditing software is hosted on the remote
web server."
  );
  script_set_attribute(attribute:"description",value:
"ADAudit Plus, a web-based Active Directory change auditing
software, was detected on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.manageengine.com/products/active-directory-audit/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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
dir = '';
page = '/Home.do';
installs = NULL;

# Only look in the root dir - this is where the installer puts
# the login page.  Also anything below the root directory will
# looks like the login page, even if the requested page
# doesn't exist
url = dir+page;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>ManageEngine - ADAudit Plus</title>' >< res[2] &&
  'ADAuditPlus Authentication' >< res[2]
)
{
  installs = add_install(
    installs:installs,
    dir:dir,
    appname:'adaudit_plus',
    port:port
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'ADAudit Plus',
      installs:installs,
      item:page,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, 'ADAudit Plus wasn\'t detected on port '+port+'.');
