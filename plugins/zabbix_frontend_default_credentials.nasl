#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70838);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:52:20 $");

  script_name(english:"Zabbix Web Interface Default Administrator Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application is protected using default administrative
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Zabbix Web Interface uses a default set of credentials
('Admin' / 'zabbix') to control access to its management interface.

With this information, an attacker can gain administrative access to
the application."
  );
  script_set_attribute(attribute:"solution", value:
"Log into the application and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("zabbix_frontend_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/zabbix");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
app = "Zabbix";

install = get_install_from_kb(
  appname      : "zabbix",
  port         : port,
  exit_on_fail : TRUE
);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install["dir"];
ver = install["ver"];
install_url = build_url(qs:dir, port:port);

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

user = "Admin";
pass = "zabbix";
url = dir + "/index.php";
login = FALSE;

# versions 1.x
if (ver =~ "^1\." || ver == UNKNOWN_VER)
{
  # Send a GET request to establish our sid
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : url,
    exit_on_fail : TRUE
  );
  match = eregmatch(pattern:'name="sid" id="sid" value="([0-9a-zA-Z]+)" ', string:res[2]);
  if (!isnull(match)) sid = match[1];
  else sid = 'xxxxxxxxxxxxxxxx';

  boundary_req = '---------------------------xxxxxxxxxxxxxxx';
  boundary = '-----------------------------xxxxxxxxxxxxxxx';

  postdata =
    boundary + '\n' +
    'Content-Disposition: form-data; name="sid"\n' +
    '\n' +
    sid + '\n' +
    boundary + '\n' +
    'Content-Disposition: form-data; name="form_refresh"\n' +
    '\n' +
    '2\n' +
    boundary + '\n' +
    'Content-Disposition: form-data; name="form"\n' +
    '\n' +
    '1\n' +
    boundary + '\n' +
    'Content-Disposition: form-data; name="name"\n' +
    '\n' +
    user + '\n' +
    boundary + '\n' +
    'Content-Disposition: form-data; name="password"\n' +
    '\n' +
    pass + '\n' +
    boundary + '\n' +
    'Content-Disposition: form-data; name="enter"\n' +
    '\n' +
    'Enter\n' +
    boundary + '--';

  res2 = http_send_recv3(
    method : "POST",
    item   : url,
    port   : port,
    data   : postdata,
    add_headers : make_array("Content-Type", "multipart/form-data; boundary=" +
      boundary_req),
    follow_redirect : 1,
    exit_on_fail    : TRUE
  );

  if (
    (
      "Welcome to Zabbix! You are connected as <b>Admin</b>" >< res2[2] &&
      'href="index.php?reconnect=1">Logout' >< res2[2]
    ) ||
    (
      res2[0] =~ "200" && 
      'window.location = "index.php"' >< res2[2]
    )
  ) login = TRUE;
}

# versions 2.0.x / 2.1.x
if (!login)
{
  clear_cookiejar();
  postdata = "request=&name="+user+"&password="+pass+"&autologin=1&enter=Sign+in";

  res = http_send_recv3(
    method : "POST",
    item   : url,
    port   : port,
    data   : postdata,
    add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"),
    follow_redirect : 1,
    exit_on_fail    : TRUE
  );
  if (
    egrep(pattern:'(href="index.php?reconnect=1")?>Logout<', string:res[2]) &&
    'href="profile.php">Profile' >< res[2]
  ) login = TRUE;
}

if (login)
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
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
