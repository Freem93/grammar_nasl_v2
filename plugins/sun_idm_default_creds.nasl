#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35105);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"Sun Java System Identity Manager Default Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application is protected with default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote installation of Sun Java System Identity Manager is
configured to use default credentials to control administrative access. 
Knowing these, an attacker can gain administrative control of the
affected application.");
  script_set_attribute(attribute:"solution", value:"Change the password for the 'Configurator' user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("sun_idm_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


user = "Configurator";
pass = "configurator";


# Test an install.
install = get_kb_item_or_exit("www/" + port + "/sun_idm");

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  install_url = build_url(qs:dir, port:port);

  # Pull up the login form.
  url = dir + "/login.jsp?lang=en&cntry=";
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    'title>Identity Manager<' >< res[2] &&
    'action="login.jsp;jsessionid=' >< res[2]
  )
  {
    # Try to log in.
    postdata =
      "id=&" +
      "command=login&" +
      "activeControl=&" +
      "accountId=" + user + "&" +
      "password=" + pass + "&";

    res = http_send_recv3(
      method:'POST',
      item:url,
      data:postdata,
      port:port,
      version:11,
      add_headers:make_array(
        "Content-Type", "application/x-www-form-urlencoded"
      ),
      exit_on_fail:TRUE
    );

    # There's a problem if we're redirected to the home page.
    if (
      "302 " >< res[0] &&
      egrep(pattern:'^Location: .+/home/index\\.jsp', string:res[1])
    )
    {
      if (report_verbosity > 0)
      {
        report =
          '\n' +
          'Nessus was able to gain access using the following credentials :\n'+
          '\n' +
          '  URL      : ' + install_url + '\n' +
          '  User     : ' + user + '\n' +
          '  Password : ' + pass + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
    else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Sun Java System Identity Manager", install_url);
  }
}
else audit(AUDIT_WEB_APP_NOT_INST, "Sun Java System Identity Manager", port);

