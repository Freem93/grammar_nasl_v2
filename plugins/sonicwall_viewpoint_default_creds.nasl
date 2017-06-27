#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56649);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");

  script_name(english:"SonicWALL ViewPoint Server Default Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to log into SonicWALL ViewPoint Server by providing the
default admin credentials.  A remote attacker could exploit this to gain
administrative control of the application."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.sonicwall.com/lat/488_3036.html");
  script_set_attribute(attribute:"solution", value:"Secure the admin account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sonicwall:viewpoint_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("sonicwall_viewpoint_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("www/sonicwall_viewpoint");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'sonicwall_viewpoint', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

install_url = build_url(qs:install['dir'], port:port);

# Get the hash which is a md5summed concatenation of a random number and the md5summed password
url = install['dir'] + '/auth';

res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:TRUE
);

# The random number is a doublequote enclosed 32-number string
match = eregmatch(pattern:'["]([0-9]{32})["]',string:res[2]);
if (!match) exit(1, "Failed to find the random number used to generate the clientHash from the SonicWALL ViewPoint Server install at "+install_url+".");
randomnumber = match[1];

# The default admin credentials
user = 'admin';
pass = 'password';

# Now we create the secure hash
hexpass = hexstr(MD5(pass));
badhash = hexstr(MD5(strcat(randomnumber, hexpass)));

# Create the post string
postdata =
  "clientHash=" + badhash + "&" +
  "needPwdChange=0&" +
  "ctlSGMSUser=" + user + "&" +
  "ctlSGMSPassword=" + pass + "&" +
  "ctlTimezoneOffset=240";

# SonicWALL appears often to be slow.
http_set_read_timeout(get_read_timeout() * 2);

# Send the post
res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  content_type:'application/x-www-form-urlencoded',
  data:postdata,
  exit_on_fail:TRUE
);

# Expect one of these responses if the password has been changed
if ('Login failed' >< res[2] || 'Invalid Credentials' >< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "SonicWALL ViewPoint Server", install_url);

# The return page after a successful login is a frame mess
if ('<blink>Frames Alert</blink>' >< res[2])
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :\n' +
      '\n' +
      '  Username : ' + user + '\n' +
      '  Password : ' + pass;

    report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(1, 'The SonicWALL ViewPoint Server install at '+install_url+' sent an unexpected response.');
