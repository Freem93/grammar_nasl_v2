#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50348);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_name(english:"IBM RSA Default Credentials");
  script_summary(english:"Logs into the IBM RSA web server with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote service is protected with default credentials.");
  script_set_attribute(attribute:"description", value:
"The IBM Remote Supervisor Adapter is configured to use the default
credentials to control access.  Knowing these, an attacker can gain
total control of the machine.");
  # http://en.wikipedia.org/wiki/IBM_Remote_Supervisor_Adapter#Default_Password
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7daaa6f2");
  script_set_attribute(attribute:"solution", value:"Edit the IBM RSA configuration and change the login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:remote_supervisor_adapter_ii_firmware");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_rsa_www.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/IBM_RSA");
  script_exclude_keys("global_settings/supplied_logins_only");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function test(port, u, p)
{
  local_var	line_limit, report, w;

  w = http_send_recv3(port: port, item: "/", method:"GET", exit_on_fail: TRUE,
    username: u, password: p, follow_redirect: 3 );
  if (w[0] !~ "^HTTP/1\.[01] 200 ") return;
  if (
    w[0] =~ "^HTTP/1\.[01] 200 " &&
    "Location:" >!< w[1] &&
    egrep(pattern:"<HTML> *<BODY[^>]*> *</BODY>", string:w[2])
  ) return;

  if (" - Login Retry Limit Exceeded</TITLE>" >< w[2])
    exit(1, "The remote server on port "+port+" rejects logins.");

  if (u == "" && p == "")
    exit(1, "The remote server on port "+port+" accepts empty credentials.");

  if (report_verbosity > 0)
  {
    line_limit = 25;
    report =
      '\n  URL      : ' + build_url(port:port, qs:'/') +
      '\n  Username : ' + u +
      '\n  Password : ' + p +
      '\n' +
      '\n' + 'Here is a snippet of the HTML response received after logging in' +
      '\n' + '(limited to ' + line_limit + ' lines) :\n' +
      '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
      beginning_of_response(resp:w[2], max_lines:line_limit) +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}

get_kb_item_or_exit("www/IBM_RSA");
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default: 80, embedded: 1);
if (!get_kb_item("www/"+port+"/IBM_RSA")) audit(AUDIT_NOT_LISTEN, "IBM RSA", port);

# Anti FP - random credentials are not safe as the card locks
# for two minutes after 5 wrong logins
test(port: port, u: "", p: "");

test(port: port, u: 'Admin', p: 'PASSW0RD');
test(port: port, u: 'USERID', p: 'PASSW0RD');

audit(AUDIT_LISTEN_NOT_VULN, "IBM RSA", port);
