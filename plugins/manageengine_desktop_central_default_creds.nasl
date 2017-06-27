#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71219);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_name(english:"ManageEngine Desktop Central Default Administrator Credentials");
  script_summary(english:"Tries to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"A web application is protected using default administrative
credentials.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Desktop Central application running on the remote
host uses a default set of credentials to control access to its
management interface. An attacker can exploit this vulnerability to
gain administrative access to the application.");
  script_set_attribute(attribute:"solution", value:
"Change the default 'admin' login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_ports("Services/www", 8020, 8383, 8040);
  script_require_keys("installed_sw/ManageEngine Desktop Central");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = "ManageEngine Desktop Central";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8020);
install = get_single_install(
  app_name            : app,
  port                : port
);

build = install["build"];
dir = install["path"];
install_url = build_url(qs:dir, port:port);

clear_cookiejar();
http_set_read_timeout(get_read_timeout() * 2);

# Get a valid session cookie
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/configurations.do",
  exit_on_fail : TRUE
);
val = get_http_cookie(name:"JSESSIONID");

build = NULL;
build_cache = NULL;

cache_match = eregmatch(pattern:'id="clearCacheBuildNum" value="(.*)"', string:res[2]);
if (!empty_or_null(cache_match)) build_cache = cache_match[1];

user = "admin";
pass = "admin";

# Versions 5.x / 6.x / 7.x
if (isnull(build_cache))
{
  postdata =
    "j_username=" + user + "&" +
    "j_password=" + pass + "&" +
    "Button=Sign+In";
}
# Versions 8.x
else
{
  postdata =
    "j_username=" + user + "&" +
    "j_password=" + pass + "&" +
    "Button=Sign+In&buildNum=" + build + "&clearCacheBuildNum=" + build_cache;
}

url = dir + "/j_security_check";
res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : url,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  follow_redirect : 2,
  exit_on_fail    : TRUE
);

# The app seems to endlessly 302 redirect during GUI scans.  Manually grab and
# request the redirect from the response
if ("homePage.do" >< res[1])
{
  match = eregmatch(pattern:"Location:(.*)(\/homePage.do(.*))", string:res[1]);
  if (!isnull(match)) link = match[2];
  # Should never reach line below
  else link = "/homePage.do?actionToCall=homePageDetails";

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + link,
    exit_on_fail : TRUE
  );
}

if (
  egrep(pattern:'a href="\\./logout\\.do" \\>Sign(&nbsp;|\\s)Out',string:res[2], icase:TRUE) &&
  'actionToCall=showAdminTab"' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :\n' +
      '\n' +
      '  Username : ' + user + '\n' +
      '  Password : ' + pass;

    report = get_vuln_report(
      items   : url,
      port    : port,
      header  : header,
      trailer : trailer
    );

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine Desktop Central", install_url);
