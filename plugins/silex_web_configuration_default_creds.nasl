#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72885);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_name(english:"Silex USB Device Server Web Configuration Page Empty Password");
  script_summary(english:"Tries to login with blank password");

  script_set_attribute(attribute:"synopsis", value:"The remote web service is protected using an empty password.");
  script_set_attribute(
    attribute:"description",
    value:
"The Web Configuration Page of the remote Silex USB Device Server uses
an empty password to manage the device.  Knowing this, an attacker
with access to the web server can gain administrative access to the
device.

Note that the device's Web Configuration Page uses host-based
authentication.  If a login has already been established from the same
host as the scanner, this plugin will not be able to test for the
credentials.

Note also that the service supports only one session at a time.  Any
login attempts from a different host while a session is active will
fail, even when the credentials are valid, which will result in false
negatives."
  );
  script_set_attribute(attribute:"solution", value:"Assign a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:silex:web_configuration_page");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

app_name = "Silex USB Device Server Web Configuration Page";

server_header = http_server_header(port:port);
if (!isnull(server_header)) audit(AUDIT_WRONG_WEB_SERVER, port, app_name);


function is_loggedin(res)
{
  if (
    '<img src="/images/logout.gif" alt="logout"' >< res[2] &&
    '>Administrative Password<' >< res[2] &&
    '>Box Name<' >< res[2] &&
    '<input type="submit" value="Save"' >< res[2]
  ) return TRUE;
  else return FALSE;
}


dir = '';
install_url = build_url(port:port, qs:dir+'/');
url = dir + '/en/private/conf/basic_main.htm';
url_logon = str_replace(find:"_main", replace:"_indx", string:url);

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (is_loggedin(res:res)) exit(0, "The "+app_name+" listening on port "+port+" did not require authentication (perhaps another login session from the same host is active).");

if (
  'name="ROOT_PASSWORD" value=""' >!< res[2] ||
  '<input type="hidden" name="path" value="'+url_logon+'">' >!< res[2] ||
  '<input type="submit" value="Login"' >!< res[2]
) exit(1, "Failed to reach the login form for "+app_name+" on port "+port+".");


if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

init_cookiejar();
pass = '';
postdata = 'ROOT_PASSWORD=' + urlencode(str:pass) + '&' +
           'path=' + urlencode(str:url);

res = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : url_logon,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  add_headers     : make_array('Referer', install_url+(url - '/')),
  exit_on_fail    : TRUE
);

if ("var currentpage = filename.substring" >< res[2])
{
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
}


if (is_loggedin(res:res))
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer = 'and an empty password.';

    report = get_vuln_report(
      items   : dir+'/',
      port    : port,
      header  : header,
      trailer : trailer
    );

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
