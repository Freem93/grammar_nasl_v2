#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16062);
 script_version("$Revision: 1.23 $");
 script_cve_id("CVE-2004-1062", "CVE-2005-4830", "CVE-2005-4831");
 script_bugtraq_id(12112, 11819);
 script_osvdb_id(3230, 12682, 13449, 34725, 34726);

 script_name(english:"ViewCVS < 1.0.0 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by cross-site scripting issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ViewCVS, a tool to browse CVS repositories
over the web written in python. 

Flaws in the remote version of this website may allow an attacker to
launch cross-site scripting and/or HTTP response-splitting attacks
against the remote install." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3821f3f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ViewCVS 1.0.0 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/29");
 script_cvs_date("$Date: 2015/02/13 21:07:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:viewcvs:viewcvs");
script_end_attributes();

 script_summary(english:"viewcvs flaw");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if( ! can_host_php(port:port) ) exit(0);
foreach dir (make_list( cgi_dirs() ) ) 
{
 r = http_send_recv3(method:"GET", item:dir + "/viewcvs.cgi/", port:port);
 if (isnull(r)) exit(0);
 res = strcat(r[0], r[1], '\r\n', r[2]);
 if ( 'Powered by<br><a href="http://viewcvs.sourceforge.net/">ViewCVS 0.' >< res )
 {
	 security_warning(port);
	 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	 exit(0);
 }
}
