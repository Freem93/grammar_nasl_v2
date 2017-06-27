#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14836);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/01/16 03:36:09 $");

  script_cve_id("CVE-2004-1559");
  script_bugtraq_id(11268);
  script_osvdb_id(10410, 10411, 10412, 10413, 10414, 10415);

  script_name(english:"WordPress < 1.2.2 Multiple XSS");
  script_summary(english:"Attempts a non-persistent XSS attack.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are affected
by cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The remote version of WordPress is vulnerable to cross-site scripting
attacks due to a failure of the application to properly sanitize user-
supplied URI input.

As a result of this vulnerability, it is possible for a remote
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. This
may facilitate the theft of cookie-based authentication credentials as
well as other attacks.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/376766");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress version 1.2.2 or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

exploit = test_cgi_xss(
  port : port,
  dirs : make_list(dir),
  cgi  : "/wp-login.php",
  qs   : "redirect_to=<script>foo</script>",
  pass_str : "<script>foo</script>",
  ctrl_re  :  '<form name="login" id="loginform" action="wp-login.php" method="post">'
);

if (!exploit)
 audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
