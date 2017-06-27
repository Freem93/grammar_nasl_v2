#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48352);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/13 20:37:05 $");

  script_bugtraq_id(42157);
  script_osvdb_id(66971);
  script_xref(name:"Secunia", value:"40850");

  script_name(english:"FuseTalk usersearchresults.cfm keyword Parameter XSS");
  script_summary(english:"Tries to inject script code through keyword parameter");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server hosts an application that is prone to a cross-
site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The installed version of FuseTalk fails to sanitize user-supplied
input to the 'keyword' parameter in file 'usersearchresults.cfm'
before using it to generate dynamic HTML content.

An unauthenticated, remote attacker may be able to leverage this issue
to inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site.");

   # http://www.thetestmanager.com/blog/2010/08/03/full-disclosure-multiple-xss-holes-in-fusetalk-forum-software/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?017610e9");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Aug/25");

  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fusetalk:fusetalk");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("fusetalk_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/fusetalk_coldfusion");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'fusetalk_coldfusion', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Try to exploit the issue.
exploit = 'ttm-"><script>alert(' + "'" + SCRIPT_NAME +"-"+unixtime() + "'" + ')</script>';

vuln = test_cgi_xss(
  port     : port,
  cgi      : "/usersearchresults.cfm",
  dirs     : make_list(dir),
  qs       : "keyword="+exploit+'&FT_ACTION=SearchUsers',
  pass_str : exploit,
  pass_re  : '(class="BoxHeaderCenter">Users that matched:|Users that matched: <b>)'
);

if (!vuln)
  exit(0, "The FuseTalk install at " + build_url(qs:dir+'/', port:port) + " is not affected.");
