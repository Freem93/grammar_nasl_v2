#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58747);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/23 22:03:55 $");

  script_cve_id("CVE-2011-4329");
  script_bugtraq_id(50617);
  script_osvdb_id(77440);

  script_name(english:"Dolibarr 3.1.0 admin/company.php username Parameter XSS");
  script_summary(english:"Tries to exploit an XSS flaw in Dolibarr");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is vulnerable to a
reflected cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Dolibarr on the remote host fails to properly sanitize
parameters in 'admin/company.php' before using them to generate
dynamic HTML.

By tricking someone into clicking on a specially crafted link, an
attacker may be able exploit this issue to inject arbitrary HTML and
script code in a user's browser to be executed within the security
context of the affected site.

Note that this install is likely affected by other XSS vulnerabilities
as well."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82be0b1a");
  script_set_attribute(attribute:"see_also", value:"https://doliforge.org/tracker/?func=detail&aid=232&group_id=144");
  script_set_attribute(attribute:"solution", value:"Upgrade to Dolibarr 3.1.1 or apply the linked patches from the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dolibarr:dolibarr");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("dolibarr_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/dolibarr");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE, embedded:0);

install = get_install_from_kb(appname:'dolibarr', port:port, exit_on_fail:TRUE);

dir = install['dir'];
xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
exploit = 'username=%22%3E' + urlencode(str:xss) + '%3Ca%20href=%22';
vuln_script = '/admin/company.php';

res = test_cgi_xss(
  port: port,
  dirs: make_list(dir),
  cgi: vuln_script,
  qs: exploit,
  pass_str: '>' + xss + '<',
  ctrl_re:  'loginfunction'
);

if (res == 0)
  exit(0, "The Dolibarr install at " + build_url(qs:dir, port:port) + " is not affected.");
