#
# Josh Zlatin-Amishav GPLv2 


include("compat.inc");

if(description)
{
 script_id(19494);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");

 script_cve_id(
  "CVE-2005-2380", 
  "CVE-2005-2381", 
  "CVE-2005-2398", 
  "CVE-2005-2399"
 );
 script_bugtraq_id(14329, 14331);
 script_osvdb_id(
  18086,
  18087,
  18088,
  18089,
  18090,
  18091,
  18092,
  18093,
  18094,
  18095,
  18096,
  18097,
  18098,
  18099,
  18100,
  18101,
  18102,
  18103,
  18104,
  18105,
  18106,
  18107,
  18108
 );

 script_name(english:"PHP Surveyor Multiple Vulnerabilities");
 script_summary(english:"Checks for SQL injection in admin.php");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP Surveyor, a set of PHP scripts used to
develop, publish and collect responses from surveys. 

The remote version of this software contains multiple vulnerabilities
that can lead to SQL injection, path disclosure and cross-site
scripting." );
 script_set_attribute(attribute:"see_also", value:"http://securityfocus.com/archive/1/405735" );
 script_set_attribute(attribute:"solution", value:"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:phpsurveyor:phpsurveyor");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2016 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/admin/admin.php?",
     "sid='"
   ), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( ("<title>PHP Surveyor</title>" >< res) && ("not a valid MySQL result" >< res))
 {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
 }
}
