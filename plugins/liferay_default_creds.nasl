#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59229);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_name(english:"Liferay Portal Default Credentials");
  script_summary(english:"Tries to access the portal with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application server uses default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote Liferay Portal by providing
default credentials.  Knowing these, an attacker can gain administrative
control of the affected application server and, for example, install
hostile plugins.");
  script_set_attribute(attribute:"solution", value:"Change the credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("liferay_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/liferay_portal");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get the ports that webservers have been found on, defaulting to
# what Liferay uses with Tomcat, their recommended bundle.
port = get_http_port(default:8080);

# Get details of the Liferay Portal install.
install = get_install_from_kb(appname:"liferay_portal", port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install["dir"];
version = install["ver"];
url = build_url(port:port, qs:dir + "/");

# Access the login page of the portal so we can get a cookie for a
# session. The number 58 cannot be changed.
url =
  "/web/guest/home" +
  "?p_auth=LHFP8z37" +
  "&p_p_id=58" +
  "&p_p_lifecycle=1" +
  "&p_p_state=maximized" +
  "&p_p_mode=view" +
  "&_58_struts_action=/login/login";

res = http_send_recv3(
  port            : port,
  method          : "GET",
  item            : url,
  exit_on_fail    : TRUE
);

# Parse the Set-Cookie headers from the HTTP response headers. Liferay
# gives clients three cookies.
regex = "^Set-Cookie: ([^;]+);";
matches = egrep(string:res[1], pattern:regex);
if (!matches) exit(1, "Failed to find Set-Cookie header in HTTP response from port " + port + ".");

# Parse the cookies from the Set-Cookie header.
cookies = make_list();
foreach match (split(matches, keep:FALSE))
{
  fields = eregmatch(string:match, pattern:regex);
  if (!isnull(fields)) cookies = make_list(cookies, fields[1]);
}

cookie = join(cookies, sep:"; ");
if (cookie == "") exit(1, "Failed to parse values from Set-Cookie headers.");

# These are the default credentials, and are known to work for 6.0.5 /
# 6.0.6. Later versions require you to change the password on first
# login.
user = "test@liferay.com";
pass = "test";

# Attempt to log in with default credentials.
res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : url,
  add_headers     : make_array("Cookie", cookie, "Content-Type", "application/x-www-form-urlencoded"),
  data            : "_58_login=" + user + "&_58_password=" + pass,
  follow_redirect : 3,
  exit_on_fail    : TRUE
);

# Check returned page to see if we're actually logged in.
if (res[2] !~ '<a *href *= *"/c/portal/logout" *> *Sign *Out')
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", url);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  header = 'Nessus was able to gain access using the following URL';
  trailer =
    'and the following set of credentials :' +
    '\n' +
    '\n  Username : ' + user +
    '\n  Password : ' + pass +
    '\n';

  report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
}

security_hole(port:port, extra:report);
