#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47163);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/15 03:38:17 $");

  script_cve_id("CVE-2010-1520");
  script_bugtraq_id(41221);
  script_osvdb_id(65846);
  script_xref(name:"Secunia", value:"40025");

  script_name(english:"TaskFreak! logout.php tznMessage Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS attack on logout.php");

  script_set_attribute(attribute:"synopsis", value:
"A PHP script hosted on the remote web server is affected by a cross-
site scripting vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of TaskFreak! on the remote host is affected by a cross-
site scripting vulnerability involving the 'tznMessage' parameter of
the 'logout.php' script.  A remote attacker may be able to exploit
this by tricking a user into making a specially crafted GET request.

There is also reportedly a SQL injection vulnerability in this version
of TaskFreak!, though Nessus has not checked for it.");

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/512078/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.taskfreak.com/original/versions");
  script_set_attribute(attribute:"solution", value:"Upgrade to TaskFreak! 0.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("taskfreak_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/taskfreak");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'taskfreak', port:port, exit_on_fail:TRUE);

dir = install['dir'];

exploit = '<script>alert(\''+SCRIPT_NAME+'-'+unixtime()+'\')</script>';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:'/logout.php',
  qs:'tznMessage='+urlencode(str:exploit),
  pass_str:'<p class="box error" style="text-align:center">'+exploit+'</p>',
  ctrl_re:'a href="http://www\\.taskfreak\\.com">TaskFreak!'
);

if (!exploited)
{
  install_url = build_url(qs:dir+'/', port:port);
  exit(0, "The TaskFreak! install at " + install_url + " is not affected.");
}
