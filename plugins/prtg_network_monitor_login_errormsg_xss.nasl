#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(51876);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_bugtraq_id(46029);
  script_osvdb_id(70670);
  script_xref(name:"Secunia", value:"43076");

  script_name(english:"PRTG Network Monitor login.htm errormsg Parameter XSS");
  script_summary(english:"Checks PRTG Network Monitor version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
cross-site scripting vulnerability." );
  script_set_attribute(attribute:"description", value:
"The installed version of PRTG Network Monitor fails to sanitize input
passed to 'errormsg' parameter in 'login.htm' before using it to
generate dynamic HTML content.

An unauthenticated, remote attacker may be able to leverage this issue
to inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site.");

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Jan/168" );
  script_set_attribute(attribute:"see_also", value:"http://www.paessler.com/prtg/prtg8history" );
  script_set_attribute(attribute:"solution", value:"Upgrade to version 8.2.0.1898/1899");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("prtg_network_monitor_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/prtg_network_monitor");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, embedded:TRUE);
install = get_install_from_kb(appname:'prtg_network_monitor', port:port, exit_on_fail:TRUE);

dir = install['dir'] + '/public' ;

exploit = "<img src='nessus' onerror='javascript:alert(/"+SCRIPT_NAME+"/)'";

vuln = test_cgi_xss(
  port     : port,
  cgi      : "/login.htm",
  dirs     :  make_list(dir),
  qs       : "errormsg="+urlencode(str:exploit),
  pass_str : "<div class=errormessage>"+exploit,
  pass_re  : '<tr><td colspan=2 class="errormessage'
);

if (!vuln)
{
  install_url = build_url(qs:install['dir'] + '/', port:port);
  exit(0, "The PRTG Network Monitor install at " + install_url + " is not affected.");
}
