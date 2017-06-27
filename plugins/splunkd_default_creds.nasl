#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49072);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/08/12 17:41:38 $");

  script_osvdb_id(67364);

  script_name(english:"Splunk Default Administrator Credentials (splunkd)");
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

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_default_creds.nasl");
  script_exclude_keys("www/splunk/default_creds","global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Splunk");
  script_require_ports("Services/www", 8089);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8089, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

install_url = build_url(qs:dir, port:port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

license = install['License'];
if (license && license == "Free")
  exit(0, "The Splunk Web install at "+install_url+" is Splunk's free version, which does not support authentication.");

# Only for the API
if (!install["isapi"])
  audit(AUDIT_WEB_APP_NOT_INST, app+" Web management API",port);

if (get_kb_item("www/splunk/default_creds") && !thorough_tests)
  exit(0, "Nessus already determined that default credentials are in use by checking the Splunk Web interface.");

# Make sure dir ends with a /
if(!dir || dir[strlen(dir) - 1] != '/') dir += '/';

url = dir + 'services';
url2 = url + '/authentication/users';

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

# Try to log in.
info = "";

user = "admin";
pass = "changeme";

res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : url2,
  username     : user,
  password     : pass,
  exit_on_fail : TRUE
);
if ("requires a Splunk Enterprise license" >< res[2])
  exit(0, "The splunkd management port at "+build_url(port:port, qs:url)+" is from Splunk's free version, which does not support authentication.");
# There's a problem if we've bypassed authentication.
if (
  '<name>Splunk</name>' >< res[2] &&
  url2+'/'+user+'</id>' >< res[2] &&
  ereg(pattern:'s:key name="roles".+<s:item>admin</s:item>', string:res[2], multiline:TRUE)
)
{
  set_kb_item(name:"www/splunk/default_creds", value:user+" / "+pass);

  info +=
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';
}

# default credentials work, but remote login is disabled.
# only report on this during paranoid scans
if (
  report_paranoia > 1 &&
  "Remote login has been disabled for '" + user + "' with the default password" >< res[2]
)
{
  replace_kb_item(name:"www/splunk/default_creds", value:user+" / "+pass);

  info +=
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n' +
    '\nNote that the service is currently configured to disallow remote login attempts.\n';
}

if (info)
{
  report = '\n' +
    'Nessus was able to gain access using the following URL :\n' +
    '\n' +
    '  ' + build_url(port:port, qs:url) + '\n' +
    '\n' +
    'and the following set of credentials :\n' +
    # nb: info already has a leading newline
    info;

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else exit(0, "The splunkd management port at "+build_url(port:port, qs:url)+" is not affected.");
