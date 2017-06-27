#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21099);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_name(english:"Adobe Document Server Default Credentials");
  script_summary(english:"Checks for default credentials in Adobe Document Server");

  script_set_attribute(attribute:"synopsis", value:
"The administration console for the remote web server is protected with
default credentials." );
  script_set_attribute(attribute:"description", value:
"The remote host is running Adobe Document Server, a server that
dynamically creates and manipulates PDF documents as well as graphic
images.

The installation of Adobe Document Server on the remote host uses the
default username and password to control access to its administrative
console.  Knowing these, an attacker can gain control of the affected
application." );
  script_set_attribute(attribute:"solution", value:
"Login via the administration interface and change the password for the
admin account." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/18");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:document_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8019);
  script_exclude_keys("global_settings/supplied_logins_only");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8019);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Default credentials.
user = "admin";
pass = "adobe";
app = "Adobe Document Server";

init_cookiejar();
# Check whether the login script exists.
r = http_send_recv3(method: 'GET', item:"/altercast/login.jsp", port:port, exit_on_fail: 1);

# If it does...
if ('<form name="loginForm" method="POST"' >< r[2])
{
  install_url = build_url(qs:"/altercast/login.jsp", port:port);
  # Extract the cookie.
  cookie = get_http_cookie(name: "JSESSIONID");
  if (isnull(cookie)) exit(1, "No JESSIONID cookie was set on port "+port+".");

  # Try to log in.
  postdata =
    "username=" + user + "&" +
    "password=" + pass + "&" +
    "submit=Sign+On";

  r = http_send_recv3(method: 'POST', port: port, item: '/altercast/login.do',
   add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
   data: postdata, version: 11, exit_on_fail: 1 );

  # There's a problem if we get a link to sign out.
  if ('<a href="logoff.jsp" class="navlink"' >< r[2])
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        'Nessus was able to gain access using the following information :\n' +
        '\n' +
        '  URL      : ' + install_url +
        '  User     : ' + user + '\n' +
        '  Password : ' + pass + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
else audit(AUDIT_WEB_APP_NOT_INST, app, port);
