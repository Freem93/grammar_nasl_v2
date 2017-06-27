#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18213);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2005-1118");
 script_bugtraq_id(13168);
 script_osvdb_id(15513);
 
 script_name(english:"RSA Security RSA Authentication Agent For Web For IIS XSS");

 script_set_attribute(
  attribute:"synopsis",
  value:
"A web application on the remote host has a cross-site scripting
vulnerability."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host appears to be running RSA Authentication Agent for
Web for IIS.

The remote version of this application fails to adequately sanitize
input to the 'postdata' variable of IISWebAgentIF.dll.  A remote
attacker could exploit this by tricking a user into requesting a
maliciously crafted URL."
 );
 script_set_attribute(
  attribute:"see_also",
  value:"http://www.oliverkarow.de/research/rsaxss.txt"
 );
 script_set_attribute(
  attribute:"solution",
  value:"Upgrade to RSA Authentication Agent for Web for IIS 5.3 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/09");
 script_cvs_date("$Date: 2015/01/15 03:38:17 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Test for XSS flaw in RSA Security RSA Authentication Agent For Web");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

req = http_get(item:'/WebID/IISWebAgentIF.dll?postdata="><script>foo</script>', port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);
if ("<TITLE>RSA SecurID " >< res && ereg(pattern:"<script>foo</script>", string:res) )
{
       security_warning(port);
       set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

