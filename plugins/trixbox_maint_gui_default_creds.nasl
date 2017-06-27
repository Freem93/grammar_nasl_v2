#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44874);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/23 20:42:25 $");

  script_name(english:"trixbox maint Web Interface Default Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"A web application is protected using default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts the web interface for trixbox (or
Asterisk@Home, as it was formerly known), a PBX application based on
Asterisk.

The remote installation of this web interface has at least one account
configured using default credentials. With this information, an
attacker can gain administrative access to trixbox and, in turn
Asterisk.");
  script_set_attribute(attribute:"solution", value:
"Change the password for the 'maint' user using, for example, the
'passwd-maint' shell script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fonality:trixbox");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("trixbox_web_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/trixbox", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

get_kb_item_or_exit("www/trixbox");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Try to log in.
info = "";
n = 0;
url = '/maint/';

users[n] = "maint";
passes[n] = "password";
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
    'trixbox - Admin Mode</TITLE>' >< res[2] ||
    'title="trixbox Admin"><b>System Status' >< res[2]
  )
  {
    info +=
      '\n  Username : ' + user +
      '\n  Password : ' + pass + '\n';

    if (!thorough_tests) break;
  }
}


if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4) s = "s";
    else s = "";

    report = '\n' +
      'Nessus was able to gain access using the following URL :\n' +
      '\n' +
      '  ' + build_url(port:port, qs:url) + '\n' +
      '\n' +
      'and the following set' + s + ' of credentials :\n' +
      # nb: info already has a leading newline
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "trixbox", build_url(port:port, qs:'/'));
