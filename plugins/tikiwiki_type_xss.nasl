#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49706);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_bugtraq_id(43507);
  script_osvdb_id(68244);
  script_xref(name:"Secunia", value:"41630");

  script_name(english:"TikiWiki 'tiki-edit_wiki_section.php' type Parameter XSS");
  script_summary(english:"Tries to inject script code through 'type' parameter");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server hosts an application that is prone to a cross-
site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The installed version of TikiWiki fails to sanitize user-supplied
input to the 'type' parameter in the 'tiki-edit_wiki_section.php'
script before using it to generate dynamic HTML content.

An unauthenticated, remote attacker may be able to leverage this issue
to inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site.

Although Nessus has not checked for them, the installed version is
also likely to be affected by several other vulnerabilities, including
cross-site request forgery and local file inclusion.");
  # http://www.johnleitch.net/Vulnerabilities/Tiki.Wiki.CMS.Groupware.5.2.Reflected.Cross-site.Scripting/44
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?339409b2");
  # http://info.tiki.org/article113-Tiki-Wiki-CMS-Groupware-Releases-5-3-and-3-8-LTS-Security-Patches
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56451e57");

  script_set_attribute(attribute:"solution", value:"Upgrade to 5.3 / 3.8 LTS.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Tiki Wiki 5.2 CMS Groupware File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);


  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tikiwiki:tikiwiki");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("tikiwiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/tikiwiki", "www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'tikiwiki', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Try to exploit the issue.
exploit = '"><script>alert(' + "'" + SCRIPT_NAME+'-'+unixtime() + "'" + ')</script>';

vuln = test_cgi_xss(
  port     : port,
  cgi      : "/tiki-edit_wiki_section.php",
  dirs     : make_list(dir),
  qs       : "type="+exploit,
  pass_str : 'class="tiki tiki_'+exploit,
  pass_re  : '/tiki-edit_wiki_section.php" *>Go back'
);

if (!vuln)
{
  install_url = build_url(qs:install['dir'] + '/', port:port);
  exit(0, "The Tiki Wiki install at " + install_url + " is not affected.");
}
