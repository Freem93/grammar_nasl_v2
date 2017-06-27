#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15479);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2004-1594");
 script_bugtraq_id(11407, 11393);
 script_osvdb_id(10722);
 
 script_name(english:"FuseTalk Forum img src Tag XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a web application that is susceptible
to cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is using FuseTalk, a web-based discussion forum.

A vulnerability exists in the script 'tombstone.cfm' that could allow 
an attacker to execute arbitrary HTML and script code in the context 
of the user's browser." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Oct/106" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/13");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks XSS in FuseTalk");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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

function check(loc)
{
 local_var r, req;
 req = http_get(item:string(loc, "/tombstone.cfm?ProfileID=<script>foo</script>"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if ( "FuseTalk Inc." >< r && egrep(pattern:"<script>foo</script>", string:r)  )
 {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
 exit(0);
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

