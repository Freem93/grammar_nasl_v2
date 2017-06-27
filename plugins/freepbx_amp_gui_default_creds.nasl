#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44873);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/08 20:42:13 $");

  script_name(english:"FreePBX / PBXconfig Default Credentials");
  script_summary(english:"Tries to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"A web application is protected using default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts FreePBX or PBXconfig, both of which are
web-based interfaces used to control and manage Asterisk.

The remote installation of the interface has at least one account
configured using default credentials. With this information, an
attacker can gain administrative access to the interface and, in turn,
to Asterisk.");
  script_set_attribute(attribute:"solution", value:
"Use the 'passwd-amp' and/or 'passwd-maint' shell scripts included with
FreePBX / PBXconfig to change any reported default password(s).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freepbx:freepbx");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("freepbx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/FreePBX");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'FreePBX';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
url = dir + '/admin/config.php';
install_loc = build_url(port:port, qs:url);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Try to log in.
info = "";
n = 0;

users[n] = "maint";
passes[n] = "password";
n++;

users[n] = "wwwadmin";
passes[n] = "password";
n++;

# http://wiki.freepbx.org/display/HTGS/2.+First+Steps+After+Installation
users[n] = "admin";
passes[n] = "admin";
n++;

# http://www.freepbx.org/support/documentation/faq/changing-the-asterisk-manager-password
users[n] = "admin";
passes[n] = "amp111";
n++;

for (i=0; i<n; i++)
{
  user = users[i];
  pass = passes[i];

  res = http_send_recv3(
    port     : port,
    method   : "GET",
    item     : url,
    exit_on_fail: 1,
    username : user,
    password : pass
  );

  # There's a problem if we've bypassed authentication.
  if (
    (
     (egrep(pattern:'<title>FreePBX (A|a)dministration',string:res[2])) &&
     ('title="logout">Logout' >< res[2])
    ) ||
    (
      ('Apply Configuration Changes' >< res[2]) &&
      ('/admin/config.php?logout">Logout<' >< res[2])
    )
  )
  {
    info +=
      '\n  Username : ' + user +
      '\n  Password : ' + pass + '\n';
  }

  else
  {
    postdata = "username=" + user + "&password=" + pass + "&submit=Login";
    res2 = http_send_recv3(
      port    : port,
      method  : "POST",
      item    : url,
      data    : postdata,
      content_type  : "application/x-www-form-urlencoded",
      exit_on_fail  : TRUE
    );

    # There's a problem if we've bypassed authentication.
    if (
     (egrep(pattern:'<title>FreePBX (A|a)dministration',string:res2[2])) &&
     ('title="logout">Logout' >< res2[2])
    )
    {
       info +=
      '\n  Username : ' + user +
      '\n  Password : ' + pass + '\n';
    }
  }

  if (!thorough_tests) break;
}


if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4) s = "s";
    else s = "";

    url = url - 'config.php';
    report = '\n' +
      'Nessus was able to gain access using the following URL :\n' +
      '\n' +
      '  ' + install_loc + '\n' +
      '\n' +
      'and the following set' + s + ' of credentials :\n' +
      # nb: info already has a leading newline
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "FreePBX / PBXconfig", install_loc);
