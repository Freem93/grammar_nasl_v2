#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14685);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");

 script_cve_id("CVE-2004-1665");
 script_bugtraq_id(11124);
 script_osvdb_id(9786);

 script_name(english:"PsNews index.php Multiple Parameter XSS");
 script_summary(english:"check PsNews XSS flaws");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
cross-site scripting issues.");
 script_set_attribute(attribute:"description", value:
"The remote server is running a version of PsNews (a content management
system) which is older than 1.2.

This version is affected by multiple cross-site scripting flaws. An
attacker may exploit these to steal the cookies from legitimate users
of this website.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Sep/66");
 script_set_attribute(attribute:"see_also", value:"http://mail.nessus.org/pipermail/nessus/2006-December/msg00024.html");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/05");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/08");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if(!port) exit(0);

if ( ! can_host_php(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
  foreach dir ( cgi_dirs() )
  {
  buf = http_get(item:dir + "/index.php?function=show_all&no=%253cscript>foo%253c/script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port:port, extra:'The following URL is vulnerable :\n' + dir + "/index.php?function=show_all&no=%253cscript>foo%253c/script>");
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
  buf = http_get(item:dir + "/index.php?function=add_kom&no=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port:port, extra:'The following URL is vulnerable :\n' + dir + "/index.php?function=add_kom&no=<script>foo</script>");
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
 }
}
