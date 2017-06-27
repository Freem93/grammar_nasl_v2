#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14647);
  script_version("$Revision: 1.25 $");

  script_cve_id("CVE-2004-1645");
  script_bugtraq_id(11071);
  script_osvdb_id(9388, 9389, 9390);
  script_xref(name:"Secunia", value:"12418");

  script_name(english:"Xedus Webserver Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Xedus Peer-to-Peer web server.
This version is vulnerable to cross-site scripting attacks.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d859f3a" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version and 
remove .x files located in ./sampledocs folder" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/30");
 script_cvs_date("$Date: 2015/01/16 03:36:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_summary(english:"Checks XSS in Xedus");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_dependencies("xedus_detect.nasl", "cross_site_scripting.nasl");
  script_family(english:"Peer-To-Peer File Sharing");
  script_require_ports("Services/www", 4274);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:4274);
if ( ! get_kb_item("xedus/" + port + "/running")) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"/test.x?username=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
  buf = http_get(item:"/TestServer.x?username=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
  buf = http_get(item:"/testgetrequest.x?param=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
  http_close_socket(soc);
 }
}
exit(0);
