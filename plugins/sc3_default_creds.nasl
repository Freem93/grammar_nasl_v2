#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36019);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_name(english:"Tenable Security Center Default Credentials");
  script_summary(english:"Attempts to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application can be accessed with default credentials.");
  script_set_attribute(attribute:"description", value:
"Tenable Network Security's Security Center, an asset-based security and
compliance monitoring application, is installed on the remote system. 
By supplying default credentials, it is possible to log into the remote
web application.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/products/sc/");
  script_set_attribute(attribute:"solution", value:
"Refer to the documentation and follow the steps to change the default
password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = "/sc3/console.php?psid=101";

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if ("Tenable Network Security's Security Center" >< res[2])
{
  install_url = build_url(port:port, qs:url);
  # Get the cookies and try to log in.

  cookie = get_http_cookie(name:"TNS_SESSIONID");
  if (!cookie) exit(0, "Unable to obtain the 'TNS_SESSIONID' session cookie value");
  cookie = "TNS_SESSIONID=" + cookie;

  vcookie = get_http_cookie(name:"TNS_VERIFYID");
  if (!vcookie) exit(0, "Unable to obtain the 'TNS_VERIFYID' session cookie value");
  vcookie = "TNS_VERIFYID=" + vcookie;

  username = "admin";
  password = "admin";

  creds = "psid=102&ctxid=default&auth2_username=" + username +
          "&auth2_password=" + base64(str:password);

  res = http_send_recv3(
         method:"POST",
         item:"/sc3/console.php?",
         port:port,
         add_headers: make_array("Content-Type", "application/x-www-form-urlencoded",
         "Cookie", (vcookie + ";" + cookie),
         "Content-Length",strlen(creds)),
         data:creds,
         exit_on_fail:TRUE
       );


  if("/sc3/console.php" >< res[1])
  {
    res = http_send_recv3(method:"GET", item:"/sc3/console.php?psid=9209",
           port:port,
           add_headers: make_array("Content-Type", "application/x-www-form-urlencoded",
           "Cookie", (vcookie + ";" +cookie)), exit_on_fail:TRUE);

    if ("Configure the Security Center" >< res[2] &&
        ">View Admin & Customer Activity Log<" >< res[2])
    {
      if(report_verbosity > 0)
      {
        report =
          '\n' +
          'Nessus could log into the web application using the following \n' +
          'credentials :\n' +
          '\n' +
          'User     : ' + username + '\n' +
          'Password : ' + password + '\n' +
          'URL      : ' + install_url +
          '\n';
        security_hole(port:port,extra:report);
      }
      else security_hole(port);
     exit(0);
    }
  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Security Center", install_url);
}
audit(AUDIT_WEB_APP_NOT_INST, "Security Center", port);
