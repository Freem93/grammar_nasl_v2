#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14614);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2004-1640");
 script_bugtraq_id(11064);
 script_osvdb_id(9393, 9394);
 
 script_name(english:"XOOPS <= 1.0 Dictionary Module Multiple Scripts XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains PHP scripts that are affected by cross-
site scripting flaws." );
 script_set_attribute(attribute:"description", value:
"The remote version of XOOPS is vulnerable to several cross-site
scripting attacks.  An attacker can exploit it using the 'terme' and
'letter' parameters of the 'search.php' and 'letter.php' scripts
respectively.  This can be used to take advantage of the trust between
a client and server allowing the malicious user to execute malicious
JavaScript on the client's machine." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109394077209963&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/28");
 script_cvs_date("$Date: 2015/01/16 03:36:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of an XSS bug in XOOPS");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("xoops_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/xoops");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 r = http_send_recv3(method: "GET", item:string(loc, "/letter.php?<script>foo</script>"), port:port);

 if (isnull(r)) exit(0);
 if('<script>foo</script>' >< r[2] )
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}
