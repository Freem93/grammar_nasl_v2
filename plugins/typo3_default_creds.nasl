#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44118);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/23 20:42:25 $");

  script_name(english:"TYPO3 Default Credentials");
  script_summary(english:"Attempts to login as admin / password.");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote TYPO3 installation by providing
the default credentials. A remote attacker can exploit this to gain
administrative control of the TYPO3 installation.");
  script_set_attribute(attribute:"solution", value:"Secure the admin account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("typo3_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

user = 'admin';
pass = 'password';

app = "TYPO3";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(qs:dir, port:port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Get the challenge token and security level prior to logging in
url = dir + '/typo3/index.php';
full_url = build_url(qs:url, port:port);
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

token_pat = '<input type="hidden" name="challenge" value="([a-f0-9]+)" />';
seclevel_pat = '<form action="index.php" method="post" name="loginform" onsubmit="doChallengeResponse\\(([^)])*\\);">';

match = eregmatch(string:res[2], pattern:token_pat);
if (empty_or_null(match[1])) exit(0, "Unable to extract challenge token from " + full_url + ".");
token = match[1];

# Checks whether or not to respond to a "super challenge" (hash the password
# before hashing the entire response)
match = eregmatch(string:res[2], pattern:seclevel_pat);
if (empty_or_null(match)) exit(0, "Unable to extract challenge mode from "+full_url+".");

if (!empty_or_null(match[1])) response = hexstr(MD5(user+':'+hexstr(MD5(pass))+':'+token));
else response = hexstr(MD5(user+':'+pass+':'+token));

# Then try to login
postdata =
  'challenge='+token+
  '&login_status=login'+
  '&userident='+response+
  '&username='+user;
res = http_send_recv3(
  method:'POST',
  item:url,
  data:postdata,
  content_type:'application/x-www-form-urlencoded',
  add_headers:make_array('Referer', 'http://'+get_host_ip()+url),
  port:port,
  exit_on_fail:TRUE
);

headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (empty_or_null(headers)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);

location = headers['location'];
if (empty_or_null(location)) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

# Successful logins are redirected to the backend admin interface.
# The name of this page differs in older versions of TYPO3
pattern = dir+'/typo3/(backend|alt_main)\\.php';
if (ereg(string:location, pattern:pattern))
{
  if (report_verbosity > 0)
  {
    report = '
Nessus was able to gain access using the following information :

  URL      : '+full_url+'
  User     : '+user+'
  Password : '+pass+'
';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
