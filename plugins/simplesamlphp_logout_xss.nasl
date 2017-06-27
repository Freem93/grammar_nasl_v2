#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57635);
  script_version("e$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_cve_id("CVE-2012-0908");
  script_bugtraq_id(51372);
  script_osvdb_id(78255);

  script_name(english:"SimpleSAMLphp logout.php link_href Parameter XSS");
  script_summary(english:"Tries to inject an XSS payload through link_href parameter");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that contains a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SimpleSAMLphp on the remote host contains a cross-site
scripting vulnerability because it fails to sanitize input to the
'link_href' parameter of the 'logout.php' script before including it
in a web page.

An attacker can leverage this issue by enticing a user to follow a
malicious URL, causing attacker-specified script code to run inside
the user's browser in the context of the affected site.  Information
harvested this way may aid in launching further attacks.

Versions of SimpleSAMLphp containing this vulnerability may also
contain another cross-site scripting vulnerability in no_cookie.php,
but this script did not test for that.");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/simplesamlphp/issues/detail?id=468");
  script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/simplesamlphp/source/detail?r=3009");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/23");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:simplesamlphp:simplesamlphp");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("simplesamlphp_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/simplesamlphp");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"simplesamlphp", port:port, exit_on_fail:TRUE);
dir = install["dir"];

cgi = "/logout.php";
xss = "javascript:alert('XSS');";

exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : cgi,
  qs       : "link_href=" + xss,
  pass_str : xss,
  ctrl_re  : 'Copyright *&copy; *[-0-9]+ *<a +href="http://rnd.feide.no/">Feide *RnD</a>'
);

if (!exploited)
  exit(0, "The SimpleSAMLphp install at " + build_url(qs:dir + cgi, port:port) + " is not affected.");
