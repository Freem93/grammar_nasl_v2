#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57580);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_cve_id("CVE-2012-0264");
  script_bugtraq_id(51212);
  script_osvdb_id(78066);

  script_name(english:"op5 Monitor Persistent Session Cookie");
  script_summary(english:"Checks whether cookies have expiry dates.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that handles session
cookies improperly.");
  script_set_attribute(attribute:"description", value:
"The remote web server has a version of op5 Monitor that improperly
handles session cookies.  The application sets an expiry date on
cookies, causing logins to persist across sessions.  Additionally,
cookies are not reissued after login.

Note that most versions affected by this vulnerability are also
affected by CVE-2012-0263, which is an information disclosure
vulnerability.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24b0cd28");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcd924ab");

  script_set_attribute(attribute:"solution", value:"Upgrade op5 Monitor to version 5.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"OP5 Monitor 5.5 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:op5:monitor");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("op5_monitor_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/op5_monitor");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get details of the op5 Monitor install.
port = get_http_port(default:443);
install = get_install_from_kb(appname:"op5_monitor", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Request the login page.
url = dir + "/";
res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : url,
  exit_on_fail : TRUE
);

# Fixed versions don't put an expiry date on the ninjasession cookie.
hdrs = egrep(string:res[1], pattern:"ninjasession=[^;]+;.*expires=[^;]+;");
if (!hdrs)
  exit(0, "op5 Monitor on port " + port + " is not affected.");

# The vulnerable version contains two identical Set-Cookie headers,
# but we only want to display one.
hdrs = split(hdrs, keep:FALSE);
hdr = hdrs[0];

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nNessus was able to verify the issue using the following request :' +
    '\n' +
    '\n  ' + build_url(port:port, qs:url) +
    '\n' +
    '\nWhich returned the following header :'+
    '\n' +
    '\n  ' + hdr +
    '\n';
}

security_warning(port:port, extra:report);
