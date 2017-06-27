#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56024);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_name(english:"HP SiteScope Default Credentials");
  script_summary(english:"Tries to access the application with default credentials.");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to log into the remote HP SiteScope instance by
providing default credentials.  This may permit creating, deleting, and
changing the passwords of SiteScope users."
  );
  script_set_attribute(attribute:"solution", value:"Change the credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/31");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:mercury_sitescope");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_sitescope_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/sitescope");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


# These are the two sets of default credentials which are in HP
# SiteScope installs. They cannot be changed during the install
# process itself, only after. The first gives administrator access,
# the second gives read-only access.
creds = make_array(
  "", "",
  "integrationViewer", "vKm46*sdH$8109#JLSudh:)"
);

# By default, SiteScope listens on port 8080.
port = get_http_port(default:8080);
install = get_install_from_kb(appname:"sitescope", port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
dir = install["dir"];


# Access the login page so we can get a cookie for a session.
res = http_send_recv3(
  port            : port,
  method          : "GET",
  item            : dir,
  follow_redirect : 3,
  exit_on_fail    : TRUE
);

# Parse the Set-Cookie headers from the HTTP response headers.
pattern = "^Set-Cookie: (JSESSIONID=[a-zA-Z0-9]+);";
matches = egrep(string:res[1], pattern:pattern);
if (!matches)
  exit(1, "Failed to find Set-Cookie header in HTTP response from port " + port + ".");

# Parse the cookie from the Set-Cookie header.
foreach match (split(matches, keep:FALSE))
{
  fields = eregmatch(string:match, pattern:pattern);
  if (!isnull(fields))
  {
    cookie = fields[1];
    break;
  }
}

if (isnull(cookie))
  exit(1, "Failed to parse value from Set-Cookie header.");

# Try to log in with each set of credentials.
logged_in = FALSE;
url = dir + "/servlet/Main";
foreach user (keys(creds))
{
  pass = creds[user];

  # Attempt to log in with default credentials.
  res = http_send_recv3(
    port            : port,
    method          : "POST",
    item            : dir + "/j_security_check",
    add_headers     : make_array("Cookie", cookie, "Content-Type", "application/x-www-form-urlencoded"),
    data            : "j_username=" + user + "&j_password=" + pass,
    follow_redirect : 3,
    exit_on_fail    : TRUE
  );

  # If the credentials were accepted, there will be a <meta> redirect
  # that will lead us to the SiteScope interface on the next page.
  res = http_send_recv3(
    port            : port,
    method          : "GET",
    item            : url,
    add_headers     : make_array("Cookie", cookie),
    follow_redirect : 3,
    exit_on_fail    : TRUE
  );

  # Check returned page to see if it is actually HP SiteScope.
  if (res[2] =~ "<TITLE> .* : HP SiteScope </TITLE>")
  {
    logged_in = TRUE;
    break;
  }
}

if (!logged_in)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP SiteScope", build_url(qs:dir, port:port));

# Report our findings.
if (report_verbosity > 0)
{
  if (user == "")
    user = "(blank)";

  if (pass == "")
    pass = "(blank)";

  header = 'Nessus was able to gain access using the following URL';
  trailer =
    'and the following set of credentials :' +
    '\n' +
    '\n  Username : ' + user +
    '\n  Password : ' + pass +
    '\n';

  report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
  security_hole(port:port, extra:report);
}
else security_hole(port:port);
