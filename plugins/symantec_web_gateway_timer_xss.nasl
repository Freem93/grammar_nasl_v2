#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59097);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/15 03:38:17 $");

  script_cve_id("CVE-2012-0296");
  script_bugtraq_id(53396);
  script_osvdb_id(81710);
  script_xref(name:"EDB-ID", value:"18832");

  script_name(english:"Symantec Web Gateway timer.php XSS (SYM12-006)");
  script_summary(english:"Attempts reflected XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web security application hosted on the remote web server has a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is hosting a version of Symantec Web Gateway
that is vulnerable to cross-site scripting attacks.  Input to the 'l'
parameter of timer.php is not properly sanitized.  An attacker could
exploit this by tricking a user into making a malicious request,
resulting in arbitrary script code execution.  There are reportedly
other cross-site scripting vulnerabilities in this version of the
software, though Nessus has not checked for those issues."
  );
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120517_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?337b743c");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Web Gateway 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/04");  
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("www/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, php:TRUE);
install = get_install_from_kb(appname:'symantec_web_gateway', port:port, exit_on_fail:TRUE);

dir = install['dir'];
cgi = '/timer.php';
xss = '<script>alert(/' + SCRIPT_NAME + '/)</script>';
qs = 'l=' + xss;
expected_output = '0 of ' + xss + ' bytes scanned';

vulnerable = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:cgi,
  qs:qs,
  pass_str:expected_output,
  ctrl_re:'<h3>Symantec Web Gateway</h3>'
);

if (!vulnerable)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Web Gateway', build_url(qs:dir, port:port));

