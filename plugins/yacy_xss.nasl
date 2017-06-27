#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16058);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2004-2651");
  script_bugtraq_id(12104);
  script_osvdb_id(12629);
  
  script_name(english:"YaCy Peer-To-Peer Search Engine XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a peer-to-peer search engine that is prone to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host runs YaCy, a peer-to-peer distributed web search
engine and caching web proxy. 

The remote version of this software is vulnerable to multiple
cross-site scripting due to a lack of sanitization of user-supplied
data. 

Successful exploitation of this issue may allow an attacker to use the
remote server to perform an attack against a third-party user." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/385453" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to YaCy 0.32 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/24");
 script_cvs_date("$Date: 2015/01/16 03:36:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:michael_christen:yacy");
script_end_attributes();

  script_summary(english:"Checks for YaCy Peer-To-Peer Search Engine XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 8080);
  script_dependencie("cross_site_scripting.nasl");
  exit(0);
}

#the code

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if ( ! get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/index.html?urlmaskfilter=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if(egrep(pattern:"<title>YaCy.+ Search Page</title>.*<script>foo</script>", string:r))
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
