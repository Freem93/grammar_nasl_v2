#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38701);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_name(english:"Oracle GlassFish Server Administration Console Default Credentials");
  script_summary(english:"Tries to access the console with default credentials.");

  script_set_attribute(attribute:"synopsis", value:"The remote web application server uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to log into the remote Oracle GlassFish administration
console by providing default credentials.  Knowing these, an attacker
can gain administrative control of the affected application server and,
for example, install hostile applets."
  );
  script_set_attribute(attribute:"solution", value:"Change the credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/07");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("glassfish_console_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/glassfish");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");


# By default, GlassFish's administration console listens on port 4848.
port = get_http_port(default:4848);

# Check if GlassFish's administration console was detected on this
# port.
get_kb_item_or_exit("www/" + port + "/glassfish/console");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Get the previously-detected version of GlassFish so we know which
# credentials to use, etc.
version = get_kb_item_or_exit("www/" + port + "/glassfish/version");
user = "admin";
if (version =~ "^2")
{
  title = "<title>.*GlassFish.*Admin Console</title>";
  pass = "adminadmin";
}
else if (version =~ "^3")
{
  title = "<title>Common Tasks</title>";
  pass = "";
}
else
  exit(0, "No known default credentials for Oracle GlassFish version " + version + " on port " + port + ".");

# Access the login page of the administration console so we can get a
# cookie for a session.
url = "/j_security_check";
res = http_send_recv3(
  port            : port,
  method          : "GET",
  item            : url,
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

# GlassFish v3 took an average of 35 seconds to respond with the HTML
# for the administration console in my tests.
if (version =~ "^3")
  http_set_read_timeout(40);

# Attempt to log in with default credentials.
res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : url,
  add_headers     : make_array("Cookie", cookie, "Content-Type", "application/x-www-form-urlencoded"),
  data            : "j_username=" + user + "&j_password=" + pass,
  follow_redirect : 3,
  exit_on_fail    : TRUE
);

# Check returned page to see if it is actually the administrative
# interface.
if (res[2] !~ title)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Oracle GlassFish", build_url(qs:"/", port:port));

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
  security_hole(port:port, extra:report);
}
else security_hole(port:port);
