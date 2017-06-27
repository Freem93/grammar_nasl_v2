#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15706);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");

 script_cve_id("CVE-2002-2010");
 script_bugtraq_id(5091);
 script_osvdb_id(7590);

 script_name(english:"ht://Dig htsearch.cgi words Parameter XSS");
 script_summary(english:"Checks if ht://Dig is vulnerable to XSS flaw in htsearch.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote contains a search engine that is affected by a cross-site
scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"The 'htsearch' CGI, which is part of the ht://Dig package, is
vulnerable to cross-site scripting attacks, through the 'words'
variable.

With a specially crafted URL, an attacker can cause arbitrary code
execution resulting in a loss of integrity.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jun/327");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/13");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencie("cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if ( ! port ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
   foreach dir (cgi_dirs())
   {
  	buf = http_get(item:string(dir,"/htsearch.cgi?words=%22%3E%3Cscript%3Efoo%3C%2Fscript%3E"), port:port);
  	r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  	if( r == NULL )exit(0);
  	if(egrep(pattern:"<script>foo</script>", string:r))
  	{
    		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	 	exit(0);
  	}
   }
}
