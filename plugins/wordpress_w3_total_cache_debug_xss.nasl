#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80553);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2014-8724");
  script_bugtraq_id(71665);
  script_osvdb_id(116040);

  script_name(english:"W3 Total Cache Plugin For WordPress Cache Key XSS");
  script_summary(english:"Attempts to inject script code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the W3 Total Cache plugin for WordPress hosted on the
remote web server fails to properly sanitize user-supplied input to
the 'Cache key' in the HTML comments displayed when 'Page cache debug
info' is enabled. An attacker can exploit this to execute arbitrary
script code within the context of the user's browser.

Note that this plugin for WordPress is also reportedly affected by
multiple cross-site request forgery (XSRF) vulnerabilities; however,
Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://www.secuvera.de/advisories/secuvera-SA-2014-01.txt");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/w3-total-cache/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 0.9.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:w3edge:total_cache");

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "wordpress_w3_total_cache_info_disclosure.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(app_name:app, port:port);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "W3 Total Cache";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

xss_test = '--><script>alert(' + unixtime() + ');</script>';
escape_xss = ereg_replace(string:xss_test, pattern:"\(", replace:"\(");
escape_xss = ereg_replace(string:escape_xss, pattern:"\)", replace:"\)");

url = "/" + xss_test;

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + url,
  fetch404     : TRUE,
  exit_on_fail : TRUE
);
pat = "Cache key:(\s)+.*" + escape_xss;

if (ereg(pattern:pat, string:res[2], multiline:TRUE))
{
  output = strstr(res[2], "<!-- W3 Total Cache:");
  if (empty_or_null(output))
  {
    output = extract_pattern_from_resp(
      string  : res[2],
      pattern : 'RE:' + pat
    );
  }
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    xss        : TRUE,
    request    : make_list(install_url + url),
    output     : chomp(output)
  );
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
