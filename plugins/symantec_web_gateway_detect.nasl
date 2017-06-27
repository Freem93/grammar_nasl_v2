#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55627);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/12 16:42:35 $");

  script_name(english:"Symantec Web Gateway Detection");
  script_summary(english:"Looks for the SWG login page");

  script_set_attribute(attribute:"synopsis", value:
"A web security application was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"Symantec Web Gateway was detected on the remote host. This application
protects against web-based malware and data loss. The host may be
configured as a Central Intelligence Unit, which provides centralized
management for multiple gateways.

Note: When HTTP credentials are configured, the anti-virus definition
version will also be reported.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/business/web-gateway");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, php:TRUE);
installs = NULL;
display_name = NULL;
url = '/spywall/login.php';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>Symantec Web Gateway</title>' >< res[2] ||       # HTTP
  '<title>Symantec Web Gateway - Login</title>' >< res[2]  # HTTPS
)
{
  display_name = 'Symantec Web Gateway';
}

if (
  '<title>Symantec Central Intelligence</title>' >< res[2] ||       # HTTP
  '<title>Symantec Central Intelligence - Login</title>' >< res[2]  # HTTPS
)
{
  display_name = 'Central Intelligence Unit';
}

if (isnull(display_name))
  exit(0, 'SWG wasn\'t detected on port ' + port);

# the version is only available on the login page when it's accessed via HTTPS
ver = NULL;
match = eregmatch(string:res[2], pattern:'Version ([0-9.]+)</td>');
if (match) ver = match[1];
else
{
  # if the version wasn't obtained (possibly because we're not using HTTPS)
  # try to get it from another page
  url = '/spywall/languageTest.php';
  res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
  match = eregmatch(string:res[2], pattern:'Software Version ([0-9.]+)');
  if (!empty_or_null(match)) ver = match[1];
}

# authenticate if credentialed scan to also obtain the database and definition
# versions from /spywall/admin_updates.php
user = get_kb_item("http/login");
pass = get_kb_item("http/password");

if (!empty_or_null(user) && !empty_or_null(pass))
{
  post_data =
    "USERNAME="+user+"&PASSWORD="+pass+"&loginBtn=Login";

  res2 = http_send_recv3(
      method      : "POST",
      item        : "/spywall/login.php",
      data        : post_data,
      port        : port,
      follow_redirect: 1,
      content_type: 'application/x-www-form-urlencoded',
      exit_on_fail: FALSE
  );

  if (res2[2] =~ "<title>Symantec Web Gateway.*Executive Summary</title>")
  {
    res3 = http_send_recv3(
        method      : "GET",
        item        : "/spywall/admin_updates.php",
        port        : port,
        exit_on_fail: FALSE
    );
    if (("Current Version" >< res3[2]) && ("Anti-Virus Version" >< res3[2]))
    {
      # version is in a blob of text with no clear anchor
      av_ver = eregmatch(pattern:"\d{8}\.\d{1,3}", string:strstr(res3[2], "Anti-Virus Version"));
      if (!empty_or_null(av_ver))
      {
        set_kb_item(
          name: 'www/' + port + '/symantec_web_gateway/av_def_ver',
          value: av_ver[0]
        );
      }
    }
  }
}

installs = add_install(
  dir:'/spywall',
  ver:ver,
  appname:'symantec_web_gateway',
  port:port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:display_name,
    installs:installs,
    port:port
  );
  if (!empty_or_null(av_ver[0]))
  {
    report += '\nSince this was a credentialed scan, the following information was also detected :\n';
    report += '\n  Anti-virus version : ' + av_ver[0] + '\n';
  }
  security_note(port:port, extra:report);
}
else security_note(port);
