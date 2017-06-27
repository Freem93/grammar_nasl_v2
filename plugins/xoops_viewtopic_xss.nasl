#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15480);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2004-2756");
  script_bugtraq_id(9497);
  script_osvdb_id(41936);

  script_name(english:"XOOPS viewtopic.php Multiple Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The weblinks module of XOOPS contains a file named 'viewtopic.php' in
the '/modules/newbb' directory.  The code of the module insufficently
filters out user provided data.  The URL parameter used by
'viewtopic.php' can be used to insert malicious HTML and/or JavaScript
in to the web page." );
 script_set_attribute(attribute:"see_also", value:"http://www.securitytracker.com/alerts/2004/Jan/1008849.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/17");
 script_cvs_date("$Date: 2011/11/28 21:39:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Detect XOOPS viewtopic.php XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("xoops_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/xoops");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port))exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 path = matches[2];

 req = http_get(item:path + '/modules/newbb/viewtopic.php?topic_id=14577&forum=2\"><script>foo</script>', port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);

 if (egrep(pattern:"<script>foo</script>", string:res))
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}
