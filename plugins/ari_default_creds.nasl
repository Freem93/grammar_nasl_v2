#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44872);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_name(english:"Asterisk Recording Interface (ARI) Default Administrator Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application is protected using default administrator
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts Asterisk Recording Interface (ARI), which
provides a web-enabled interface for Asterisk users to manage their
voicemail and phone features.

The remote installation of ARI uses a default set of credentials for
the administrator's account.  With this information, an attacker can
gain administrative access to the application."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Edit the application's 'includes/main.conf.php' file and change the
values for '$ARI_ADMIN_USERNAME' and/or '$ARI_ADMIN_PASSWORD'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = '/recordings/index.php';

# Unless we're paranoid, make sure it looks like ARI.
if (report_paranoia < 2)
{
  res = http_get_cache(item:url, port:port, exit_on_fail: 1);

  if (
    "input type='text' name='username'" >!< res &&
    "input type='password' name='password'" >!< res &&
    'Voicemail Mailbox and Password' >!< res &&
    'from Littlejohn Consulting</a>' >!< res
  ) exit(0, "ARI does not appear to be not running at "+build_url(port:port, qs:url)+".");
}


# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();


# Try to log in.
info = "";
n = 0;

users[n] = "admin";
passes[n] = "ari_password";
n++;

for (i=0; i<n; i++)
{
  user = users[i];
  pass = passes[i];

  postdata =
    "username=" + user + "&" +
    "password=" + pass + "&" +
    "submit=Submit";

  res = http_send_recv3(
    port        : port,
    method      : 'POST',
    item        : url,
    data        : postdata,
    add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"),
    exit_on_fail: TRUE
  );

  # There's a problem if we've bypassed authentication.
  if (
    "?m=Voicemail&f=display'>Voicemail" >< res[2] ||
    "?m=PhoneFeatures&f=display'>Phone Features" >< res[2] ||
    '<h2>Call Monitor</h2>' >< res[2]
  )
  {
    info +=
      '\n  Username : ' + user +
      '\n  Password : ' + pass + '\n';

    if (!thorough_tests) break;
  }
}

install_url = build_url(port:port, qs:url);
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4) s = "s";
    else s = "";

    report = '\n' +
      'Nessus was able to gain access using the following URL :\n' +
      '\n' +
      '  ' + install_url + '\n' +
      '\n' +
      'and the following set' + s + ' of credentials :\n' +
      # nb: info already has a leading newline
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Asterisk Recording Interface (ARI)", install_url);
