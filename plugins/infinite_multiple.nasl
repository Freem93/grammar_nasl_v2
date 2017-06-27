#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16278);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-2005-0323", "CVE-2005-0324");
 script_bugtraq_id(12399);
 script_osvdb_id(13320, 13321);

 script_name(english:"Infinite Mobile Delivery Webmail Multiple Vulnerabilities (XSS, PD)");
 script_summary(english:"Checks for the presence of Infinite Mobile Delivery");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a webmail application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"There are flaws in the remote Infinite Mobile Delivery, a web 
interface to provide wireless access to mail.

This version of Infinite Mobile Delivery has a cross-site scripting
vulnerability and a path disclosure vulnerability. 

An attacker, exploiting this flaw, would be able to steal user 
credentials or use disclosed information to launch further attacks." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/363" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/29");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
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

function check(loc)
{
 local_var res;

 res = http_send_recv3(method:"GET", item:string(loc, "/"),port:port);
 if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

 if ( egrep(pattern:"^Powered by .*Infinite Mobile Delivery v([0-1]\..*|2\.[0-6]).* -- &copy; Copyright [0-9]+-[0-9]+ by .*Captaris", string:res[2]))
 {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

