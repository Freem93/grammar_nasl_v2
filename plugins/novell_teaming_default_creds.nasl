#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47804);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_name(english:"Novell Teaming Default Credentials");
  script_summary(english:"Attempts to log in with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a web application that uses default
login credentials.");
  script_set_attribute(attribute:"description", value:
"The installed version of Novell Teaming hosted on the remote web server
uses the default username and password to control access to its
administrative console. 

Knowing these, an attacker can gain control of the affected
application.");
  script_set_attribute(attribute:"solution", value:
"Login via the administrative interface and change the password for the
'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("novell_teaming_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("www/novell_teaming");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

install = get_install_from_kb(appname:'novell_teaming', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = 'admin';
pass = 'admin';

url = build_url(port:port, qs:install['dir']+'/ssf/a/');
postdata = 'j_username='+user+'&j_password='+pass+'&okBtn=OK&spring-security-redirect='+url+'do?p_name=ss_formum&p_action=1&binderId=2&action=view_ws_listing&entryID=ss_user_id_place_holder';
req = http_mk_post_req(
  port:port,
  item:install['dir']+'/ssf/a/ssf/s/portalLogin',
  add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"),
  data:postdata
);
res = http_send_recv_req(port:port, req:req, follow_redirect:2, exit_on_fail:TRUE);
if (
  '<title>Personal Workspaces</title>' >< res[2] &&
  '<span class="ss_tree_highlight_not">Home Workspace</span>' >< res[2] &&
  'alt="About Novell Teaming"' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to gain access to the administrative interface using' +
      '\nthe following information :' +
      '\n' +
      '\n  URL      : ' + build_url(port:port, qs:install['dir']+'/') +
      '\n  User     : ' + user +
      '\n  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Novell Teaming", build_url(port:port, qs:install['dir']));
