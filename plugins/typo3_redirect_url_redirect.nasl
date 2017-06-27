#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48239);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_bugtraq_id(42029);
  script_xref(name:"Secunia", value:"40742");

  script_name(english:"TYPO3 Back-end 'index.php' 'redirect_url' Redirect");
  script_summary(english:"Attempts to exploit the redirect weakness.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts an application with an open redirect.");
  script_set_attribute(attribute:"description", value:
"The installed version of TYPO3 fails to validate input passed to the
'redirect_url' parameter of the back-end 'index.php' script before
issuing a redirect. An attacker can exploit this issue to conduct
phishing attacks by tricking users into visiting malicious websites.

The installed version is also reportedly affected by several other
vulnerabilities including cross-site scripting, SQL-injection,
arbitrary code execution, information disclosure, header injection,
broken authentication, and session management; however, Nessus has not
tested for these issues.");
  script_set_attribute(attribute:"see_also", value:"http://typo3.org/teams/security/security-bulletins/typo3-sa-2010-012/");
  script_set_attribute(attribute:"solution", value:"Upgrade to TYPO3 4.1.14 / 4.2.13 / 4.3.4 / 4.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "TYPO3";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(qs:dir, port:port);

redirect = "http://www.example.com";
url = '/typo3/index.php';
exploit = url + "?L=OUT&redirect_url="+ redirect;

res = http_send_recv3(method:"GET", item:dir+exploit, port:port, exit_on_fail:TRUE);

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (empty_or_null(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

if (empty_or_null(hdrs['location'])) location = "";
else location = hdrs['location'];

# There's a problem if ...
if (
  # we're redirected and ...
  code == 302 &&
  # it's to the location we specified
  redirect == location
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to verify the issue using the following URL :' + '\n' +
      '\n' +
      ' ' + install_url + exploit + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
