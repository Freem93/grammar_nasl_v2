#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15514);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");

 script_cve_id("CVE-2004-1621");
 script_bugtraq_id(11458);
 script_osvdb_id(10966);

 script_name(english:"IBM Lotus Notes/Domino Square Brackets Encoding Failure XSS");
 script_summary(english:"Checks for Lotus Domino XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a cross-site scripting attack.");
 script_set_attribute(attribute:"description", value:
"The remote server is vulnerable to cross-site scripting, when requesting 
a .nsf file with html arguments, as in :

GET /FormReflectingURLValue?OpenForm&Field=[XSS]");
 script_set_attribute(attribute:"solution", value:
"None at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/19");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/18");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/10/18");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( "Lotus Domino" >!< banner ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

	
r = http_send_recv3(item:"/FormReflectingURLValue?OpenForm&Field=%5b%3cscript%3efoo%3cscript%3e%5d", port:port, method: "GET");
if (isnull(r)) exit (0);
if ( "<script>foo</script>" >< r[2] )
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
