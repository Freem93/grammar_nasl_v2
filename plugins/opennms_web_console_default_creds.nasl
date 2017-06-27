#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34351);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_name(english:"OpenNMS Web Console Default Credentials");
  script_summary(english:"Tries to login to the web console with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application is protected with default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote OpenNMS Web Console is configured to use default credentials
to control administrative access.  Knowing these, an attacker can gain
administrative control of the affected application.");
  script_set_attribute(attribute:"solution", value:"Change the password for the 'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("opennms_web_console_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8980);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8980);

user = "admin";
pass = "admin";


# Test an install.
install = get_kb_item_or_exit("www/" + port + "/opennms");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  init_cookiejar();
  # Get a session cookie.
  r = http_send_recv3(method: "GET", item:dir + "/acegilogin.jsp", port:port, exit_on_fail:TRUE);

  cookie = "";
  if ('<form action="j_acegi_security_check;jsessionid=' >< r[2])
  {
    cookie = strstr(r[2], '<form action="j_acegi_security_check;jsessionid=') -
             '<form action="j_acegi_security_check;jsessionid=';
    cookie = cookie - strstr(cookie, '"');
  }

  if (cookie)
  {
    # Try to log in.
    postdata = 
      "j_username=" + user + "&" +
      "j_password=" + pass + "&" +
      "Login=Login";
    set_http_cookie(name: "JSESSIONID", value: cookie);
    r = http_send_recv3(
      method : "POST",
      item   : dir + "/j_acegi_security_check",
      port   : port,
      version: 11,
      data   : postdata,
      add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"), 
     exit_on_fail : TRUE);

    # If we didn't see a failure message...
    if ('/acegilogin.jsp?login_error=1' >!< r[2])
    {
      # Make sure we really can get in.
      r = http_send_recv3(method: "GET", item:dir + "/index.jsp", port:port, exit_on_fail:TRUE);

      # There's a problem if we can.
      if (
        '<a href="j_acegi_logout">' >< r[2] &&
        '<a href="dashboard.jsp">' >< r[2]
      )
      {
        if (report_verbosity > 0)
        {
          report =
            '\n' +
            'Nessus was able to gain access using the following credentials :\n' +
            '\n' +
            '  User     : ' + user + '\n' +
            '  Password : ' + pass + '\n';
          security_hole(port:port, extra:report);
        }
        else security_hole(port);
      }
    }
    else audit(AUDIT_WEB_APP_NOT_AFFECTED, "OpenNMS", build_url(qs:dir, port:port));
  }
  else
  {
    exit(0,"Nessus was unable to obtain the session cookie!");
  }
}
else audit(AUDIT_WEB_APP_NOT_INST, "OpenNMS", port);
