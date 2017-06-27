#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65950);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/17 21:12:12 $");

  script_name(english:"Citrix Access Gateway Administrative Web Interface Default Credentials");
  script_summary(english:"Tries to access the admin web interface with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote Citrix Access Gateway
administrative web interface by providing default credentials.  Knowing
these, an attacker can gain administrative control of the affected
application server and, for example, upload a new system image.");
  script_set_attribute(attribute:"solution", value:"Change the default credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX129498");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:access_gateway");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("citrix_access_gateway_admin_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/citrix_access_gateway_admin");
  script_require_ports("Services/www", 443, 9001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

global_var dir, port;

app = "Citrix Access Gateway Administrative Web Interface";

function v4_login()
{
  local_var pass, res, url, user;

  # These are the default credentials, and are known to work for the
  # v4 branch.
  user = "root";
  pass = "rootadmin";

  # v4 uses plain HTTP basic auth.
  url = dir + "/administration.html";
  res = http_send_recv3(
    port     : port,
    method   : "GET",
    item     : url,
    username : user,
    password : pass
  );

  if (isnull(res) || res[0] =~ "^401 " || res[2] !~ '<title> *Administration +Tool *</title>')
    return FALSE;

  # Return the credentials and URL.
  return make_list(url, user, pass);
}

function v5_login()
{
  local_var f_pass, f_user, hdrs, matches, pass, re1, re2, res, url;
  local_var user;

  # All the CAG interfaces are powered by the Yahoo! UI library, which
  # gives nonce-y names to fields. Since the field names are generated
  # and differ between builds, we need to fail a login an scrape them
  # from the login form.
  #
  # The POST data must be sent to prevent a server error.
  url = dir + "/u/LoginAuth.do";
  hdrs = make_array("Content-Type", "application/x-www-form-urlencoded");
  res = http_send_recv3(
    port        : port,
    method      : "POST",
    item        : url,
    data        : "lpname=AdminLogonPoint",
    add_headers : hdrs
  );

  if (isnull(res) || res[2] !~ 'class="agxLoginEntry[^"]*"')
    return FALSE;

  re1 = '<tr><td[^>]*>';
  re2 = ':</td><td[^>]*><input +name *= *"([^"]*)"[^>]*></td></tr>';

  matches = eregmatch(string:res[2], pattern:re1 + "User&nbsp;name" + re2);
  if (isnull(matches))
    return FALSE;
  f_user = matches[1];

  matches = eregmatch(string:res[2], pattern:re1 + "Password" + re2);
  if (isnull(matches))
    return FALSE;
  f_pass = matches[1];

  # These are the default credentials, and are known to work for the
  # v5 branch.
  user = "admin";
  pass = "admin";

  # Attempt to log in with default credentials.
  res = http_send_recv3(
    port        : port,
    method      : "POST",
    item        : url,
    data        : "lpname=AdminLogonPoint&" + f_user + "=" + user + "&" + f_pass + "=" + pass,
    add_headers : hdrs
  );

  # Check response, which will be JSON on success and HTML on failure.
  if (isnull(res) || res[2] !~ '\\{ *"login" *: *\\[ *\\{ *"status" *: *0 *,')
    return FALSE;

  # Return the credentials and URL.
  return make_list(url, user, pass);
}

# Get the ports that webservers have been found on, defaulting to what
# the CAG uses as of v5.
port = get_http_port(default:443);

# Get details of the CAG install.
install = get_install_from_kb(appname:"citrix_access_gateway_admin", port:port, exit_on_fail:TRUE);

# Bail if the policy forbids these kinds of checks.
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install["dir"];

# Try each version in turn.
creds = v4_login();
if (!creds)
  creds = v5_login();

if (!creds)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:dir));

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  header = 'Nessus was able to gain access using the following URL';
  trailer =
    'and the following set of credentials :' +
    '\n' +
    '\n  Username : ' + creds[1] +
    '\n  Password : ' + creds[2] +
    '\n';

  report = get_vuln_report(items:creds[0], port:port, header:header, trailer:trailer);
}

security_hole(port:port, extra:report);
