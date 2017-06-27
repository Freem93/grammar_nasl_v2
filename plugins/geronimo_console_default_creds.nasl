#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20736);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_name(english:"Geronimo Console Default Credentials");
  script_summary(english:"Checks for default credentials in Geronimo console");

  script_set_attribute(attribute:"synopsis", value:
"The administration console for the remote web server is protected with
default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Geronimo, an open source J2EE
server from the Apache Software Foundation. 

The installation of Geronimo on the remote host uses the default
username and password to control access to its administrative console. 
Knowing these, an attacker can gain control of the affected
application.");
  script_set_attribute(attribute:"solution", value:
"Alter the credentials in 'var/security/users.properties' or when
deploying Geronimo.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value: "cpe:/a:apache:geronimo");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080, embedded: 0);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


# Check whether the login script exists.
foreach url (make_list("/console/portal/", "/console/login.jsp"))
{
  init_cookiejar();

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  # If it does...
  if ('form name="login" action="j_security_check"' >< res[2])
  {
    # Extract the cookie.
    val = get_http_cookie(name:"JSESSIONID");
    if (isnull(val))
    {
      debug_print("can't extract the session cookie!\n");
      continue;
    }

    # Try to log in.
    user = "system";
    pass = "manager";
    postdata =
      "j_username=" + user + "&" +
      "j_password=" + pass + "&" +
      "submit=Login";

    if ("login.jsp" >< url) url2 = "/console/j_security_check";
    else url2 = url + "/j_security_check";

    res = http_send_recv3(
      port        : port,
      method      : 'POST',
      item        : url2,
      version     : 11,
      data        : postdata,
      add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"),
      exit_on_fail: TRUE
    );

    # There's a problem if we get redirected to the console itself
    # rather than an error page (eg, "/console/loginerror.jsp").
    if (egrep(pattern:"^Location: +https?://[^/]+/console", string:res[1]))
    {
      if (report_verbosity > 0)
      {
        report =
          '\n' +
          'Nessus was able to gain access using the following credentials :\n' +
          '\n' +
          '  URL      : ' + build_url(port:port, qs:url) + '\n' +
          '  User     : ' + user + '\n' +
          '  Password : ' + pass + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Geronimo", build_url(port:port, qs:"/console/"));
