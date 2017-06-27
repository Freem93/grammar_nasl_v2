#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49071);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_osvdb_id(67364);

  script_name(english:"Splunk Default Administrator Credentials (Splunk Web)");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is protected using
default administrator credentials.");
  script_set_attribute(attribute:"description", value:
"The version of Splunk hosted on the remote web server uses a default
set of credentials for the default administrator account. A remote
attacker can exploit this to gain administrative access to the
application.");
  # http://docs.splunk.com/Documentation/Splunk/3.4/User/ChangeDefaultSplunkServerSettings
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46e3469c");
  script_set_attribute(attribute:"solution", value:
"Change the administrator password either by logging into the Splunk
Web Manager or by using the CLI command 'splunk edit user'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("splunk_web_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

install_url = build_url(qs:dir, port:port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

license = intstall['License'];
if (license && license == "Free")
  exit(0, "The Splunk Web install at "+install_url+" is Splunk's free version, which does not support authentication.");

# Only for the WebUI
if (!install["isweb"])
  audit(AUDIT_WEB_APP_NOT_INST, app+" Web interface",port);

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Get the login form .
res = http_send_recv3(
  port            : port,
  method          : "GET",
  item            : dir+'/',
  follow_redirect : 2,
  exit_on_fail    : TRUE
);

if ('"licenseType: "free"' >< res[2])
  exit(0, "The Splunk Web install at "+install_url+" is from Splunk's Free version, which does not support authentication.");

# Extract the necessary info from the form.
url = "";
cval = NULL;

if (
  '<form action="/' >< res[2] &&
  '<input type="password" name="password"' >< res[2]
)
{
  url = strstr(res[2], '<form action="') - '<form action="';
  url = url - strstr(url, '"');
  if ('\n' >< url || !ereg(pattern:"^/[^ '<>]*account/login$", string:url)) url = "";

  if ('name="cval" value="' >< res[2])
  {
    cval = strstr(res[2], 'name="cval" value="') - 'name="cval" value="';
    cval = cval - strstr(cval, '"');
    if ('\n' >< cval || ereg(pattern:"[ '<>]", string:cval)) cval = NULL;
  }
}
if (!url) exit(1, "Failed to identify the login URL for the Splunk Web install at "+install_url+".");
base_url = url-'account/login';

# Try to log in.
info = "";

user = "admin";
pass = "changeme";

postdata =
  'return_to=' + urlencode(str:base_url) + '&' +
  'username=' + user + '&' +
  'password=' + pass;
if (!isnull(cval)) postdata = 'cval='+cval+'&'+postdata;

res = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : url,
  data            : postdata,
  add_headers     : make_array("Content-Type", "application/x-www-form-urlencoded"),
  follow_redirect : 2,
  exit_on_fail    : TRUE
);

# There's a problem if
if (
  # we're redirected to the licensing page or...
  (
    '303 ' >< res[0] &&
    ( ('Location: '+build_url(port:port, qs:base_url+'licensing') >< res[1]) ||
      (egrep(pattern:'Set-Cookie: (splunkweb_csrf_token|session_id_8000)', string:res[1]))
    )
  ) ||
  # we've bypassed authentication
  (
    res[2] &&
    ( ('Logged in as admin' >< res[2]) || ('"USERNAME": "admin"' >< res[2]) ) &&
    ('app/launcher/job_management' >< res[2] || '>Logout</a>' >< res[2])
  )
)
{
  # nb: this is used by splunkd_default_creds.nasl
  set_kb_item(name:"www/splunk/default_creds", value:user+" / "+pass);

  info +=
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';
}

if (info)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n' + 'Nessus was able to gain access using the following URL :' +
      '\n' +
      '\n' + '  ' + build_url(port:port, qs:url) + 
      '\n' +
      '\n' + 'and the following set of credentials :' +
      '\n' +
      # nb: info already has a leading newline
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
