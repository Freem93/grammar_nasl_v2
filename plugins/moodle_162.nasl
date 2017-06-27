#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22364);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/11/18 21:03:57 $");

  script_cve_id("CVE-2006-4784", "CVE-2006-4785", "CVE-2006-4786");
  script_bugtraq_id(19995, 20085);
  script_osvdb_id(
    28792,
    28793,
    28794,
    28795,
    28796,
    28797,
    28798,
    28799,
    28800,
    28801,
    30841
  );

  script_name(english:"Moodle < 1.6.2 Multiple Vulnerabilities");
  script_summary(english:"Checks if Moodle's 'jumpto.php' requires a sesskey.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Moodle fails to sanitize user-supplied input
to a number of parameters and scripts. An attacker can leverage these
issues to launch SQL injection and cross-site scripting attacks
against the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/446227/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://docs.moodle.org/en/Release_Notes#Moodle_1.6.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Moodle version 1.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Request a redirect.
xss = "nessus.php?";
r = http_send_recv3(method: "GET",
    item:dir + "/course/jumpto.php?jump=" + urlencode(str:xss),
    port:port, follow_redirect: 0, exit_on_fail:TRUE
);

# There's a problem if...
if (
  # we get a session cookie for Moodle and...
  "MoodleSession=" >< r[0] &&
  # we're redirected
  "location.replace('" + xss + "')" >< r[2]
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
