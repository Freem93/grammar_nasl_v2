#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, commented incorrect CVE/BID (5/21/09)
# - Revised plugin synopsis and description (5/27/2011)


include("compat.inc");

if(description)
{
 script_id(10853);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");

# script_cve_id("CVE-2002-0569");
# script_bugtraq_id(4298);
 script_osvdb_id(710);

 script_name(english:"Oracle 9iAS mod_plsql Multiple Procedures XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross-site scripting." );
 script_set_attribute(attribute:"description", value:
"The mod_plsql module supplied with Oracle9iAS allows cross-site scripting 
attacks to be performed." );
 script_set_attribute(attribute:"solution", value:
"Patches which address several vulnerabilities in Oracle 9iAS can be 
downloaded from the oracle Metalink site." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
 script_set_attribute(attribute:"see_also", value:"http://www.nextgenss.com/papers/hpoas.pdf");
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/02/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/01/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
 script_end_attributes();

 
 script_summary(english:"Tests for Oracle 9iAS mod_plsql cross-site scripting");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Matt Moore");
 script_family(english: "CGI abuses : XSS");
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

req = http_get(item:"/pls/help/<SCRIPT>alert(document.domain)</SCRIPT>",
 		port:port);
soc = http_open_socket(port);
if(soc)
{
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 confirmed = string("<SCRIPT>alert(document.domain)</SCRIPT>");
 confirmedtoo = string("No DAD configuration");
 if((confirmed >< r) && (confirmedtoo >< r))
 {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}

