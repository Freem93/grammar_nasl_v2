#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15785);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2011/11/28 21:39:45 $");

 script_cve_id("CVE-2004-2725");
 script_bugtraq_id( 11654 );
 script_osvdb_id(11704);
 
 script_name(english:"Aztek Forum Multiple Script XSS");
 script_summary(english:"Checks XSS in Aztek Forum");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
cross-site scripting issue");
 script_set_attribute(attribute:"description", value:
"The remote host is using Aztek Forum, a web forum written in PHP. 

A vulnerability exists the remote version of this software - more
specifically in the script 'forum_2.php', that may allow an attacker
to set up a cross-site scripting attack using the remote host.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/22");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/13");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit ( 0 );

global_var port;

function check_dir(path)
{
 local_var req, res;

 req = http_get(item:string(path, "/forum_2.php?msg=10&return=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(1, "The web server on port "+port+" failed to respond.");

 if ( "forum_2.php?page=<script>foo</script>" >< res )
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check_dir(path:dir);
}
 
